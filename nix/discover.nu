# A host's LAN address changes with every network it joins, so each host shouts
# "I'm here" on its NICs and whoever dials it follows. A replayed shout can
# still aim a link somewhere wrong, so every move is on probation until a
# handshake answers. The id rotates every 10 minutes so the host can't be
# followed around by its public key.
def hmac [key: string, message: string] {
   let pad = {|byte: binary, count: int| if $count == 0 { 0x[] } else { 1..$count | each { $byte } | bytes collect } }
   let raw = $key | into binary
   let short = if ($raw | bytes length) > 64 { $raw | hash sha256 --binary } else { $raw }
   let block = $short | bytes add --end (do $pad 0x[00] (64 - ($short | bytes length)))
   let inner = $block | bits xor (do $pad 0x[36] 64) | bytes add --end ($message | into binary) | hash sha256 --binary
   $block | bits xor (do $pad 0x[5c] 64) | bytes add --end $inner | hash sha256 | str substring 0..31
}

def window [] {
   (date now | into int) // 600_000_000_000
}

def nics [] {
   if $nu.os-info.name == "macos" {
      ^networksetup -listallhardwareports
      | split row "\n\n"
      | where {|block| $block =~ "Device: en" }
      | each {|block| $block | lines | parse "{field}: {value}" | transpose --header-row --as-record }
      | each {|port|
         ^ifconfig $port.Device
         | parse --regex 'inet (?<address>[\d.]+) netmask 0x(?<mask>[0-9a-f]+) broadcast (?<broadcast>[\d.]+)'
         | each {|inet|
            let prefix = $inet.mask | into int --radix 16 | format bits | split chars | where $it == "1" | length
            { address: $inet.address, broadcast: $inet.broadcast, prefix: $prefix, wired: (not ($port."Hardware Port" =~ "Wi-Fi")) }
         }
      }
      | flatten
   } else {
      ^ip -4 -json address show
      | from json
      | where {|nic| $"/sys/class/net/($nic.ifname)/device" | path exists }
      | each {|nic|
         let wired = not ($"/sys/class/net/($nic.ifname)/wireless" | path exists)
         $nic.addr_info
         | where {|info| $info.family == "inet" and $info.broadcast? != null }
         | each {|info| { address: $info.local, broadcast: $info.broadcast, prefix: $info.prefixlen, wired: $wired } }
      }
      | flatten
   }
}

def ip4 [address: string] {
   $address | split row "." | each { into int } | reduce --fold 0 {|octet, total| ($total bit-shl 8) bit-or $octet }
}

# Broadcasts never cross a router, so a shout naming an address outside every
# local subnet was relayed from another LAN.
def subnets [] {
   nics | each {|nic|
      let mask = if $nic.prefix == 0 { 0 } else { (0xffffffff bit-shl (32 - $nic.prefix)) bit-and 0xffffffff }
      { mask: $mask, network: ((ip4 $nic.address) bit-and $mask) }
   }
}

def onlink [subnets: list, address: string] {
   let target = ip4 $address
   $subnets | any {|subnet| ($target bit-and $subnet.mask) == $subnet.network }
}

# Every shout starts with a newline, so a stray datagram without one can't glue
# itself onto the front of the next real shout.
def send [port: int, key: string, secret: string] {
   loop {
      try {
         let id = hmac $secret $"(window) ($key)"
         let time = (date now | into int) // 1_000_000_000
         for nic in (nics) {
            let medium = if $nic.wired { "wired" } else { "wireless" }
            let seal = hmac $secret $"($id) ($nic.address) ($time) ($medium)"
            try {
               $"\n($nic.address) ($id) ($time) ($seal) ($medium)\n"
               | ^socat -u STDIN $"UDP4-DATAGRAM:($nic.broadcast):($port),broadcast,bind=($nic.address)"
            }
         }
      } catch {|error|
         print --stderr $"shout failed: ($error.msg)"
      }
      sleep 5sec
   }
}

def device [link: record, utun: bool] {
   if $utun { open --raw $"/var/run/wireguard/($link.name).name" | str trim } else { $link.name }
}

# Moving a live peer keeps its session, and WireGuard won't rekey for up to two
# minutes, so the peer is dropped and re-added to force a handshake that proves
# the new endpoint answers.
def repoint [device: string, link: record, endpoint: string] {
   let target = if $endpoint == "(none)" { [] } else { [endpoint $endpoint] }
   (^wg set $device peer $link.publicKey remove
      peer $link.publicKey allowed-ips ($link.allowedIPs | str join ",") ...$target persistent-keepalive 25)
}

# A sealed shout only proves the host was at that address within the last 30s,
# and a relay can still carry it to another LAN. So a move has 15s to complete
# a handshake, or it's undone and that address is ignored for a minute,
# doubling on each repeat up to 10.
def settle [state: record, now: int, utun: bool] {
   let due = $state.trials | where {|trial| $now - $trial.at >= 15_000_000_000 }
   let failed = $due | where {|trial|
      try {
         let handshake = ^wg show (device $trial.link $utun) latest-handshakes | parse "{peer}\t{time}" | get --optional 0.time | default "0" | into int
         $handshake < $trial.at // 1_000_000_000
      } catch {
         false
      }
   }

   for trial in $failed {
      try {
         repoint (device $trial.link $utun) $trial.link $trial.previous
         let undo = if $trial.previous == "(none)" { "cleared" } else { $"back to ($trial.previous)" }
         print $"($trial.link.peer) never answered at ($trial.address), ($undo)"
      }
   }

   $state
   | update trials { where {|trial| $now - $trial.at < 15_000_000_000 } }
   | update banned {
      let bans = $in | where {|ban| $now - $ban.until < 600_000_000_000 }
      let fresh = $failed | each {|trial|
         let strikes = $bans | where {|ban| $ban.peer == $trial.link.peer and $ban.address == $trial.address } | get --optional 0.strikes | default 0
         let span = [(60_000_000_000 * (2 ** $strikes)) 600_000_000_000] | math min
         { peer: $trial.link.peer, address: $trial.address, until: ($now + $span), strikes: ([($strikes + 1) 4] | math min) }
      }
      $bans | where {|ban| not ($fresh | any {|new| $new.peer == $ban.peer and $new.address == $ban.address }) } | append $fresh
   }
}

# A link moves when its session is dead, its address goes quiet, or Ethernet
# shows up next to Wi-Fi. Wi-Fi shouts wait out 15s of wired silence.
def receive [links: list, port: int, secret: string, utun: bool] {
   ^socat -u $"UDP4-RECV:($port),reuseaddr" STDOUT
   | lines
   | reduce --fold { epoch: null, ids: [], heard: [], trials: [], banned: [], subnets: [], scanned: 0 } {|line, before|
      let now = date now | into int
      let state = settle $before $now $utun

      let shout = $line
         | parse --regex '^(?<address>\d{1,3}(?:\.\d{1,3}){3}) (?<id>[0-9a-f]{32}) (?<time>\d{1,12}) (?<seal>[0-9a-f]{32}) (?<medium>wired|wireless)$'
         | get --optional 0
      if $shout == null { return $state }
      if (($now // 1_000_000_000) - ($shout.time | into int) | math abs) > 30 { return $state }

      let epoch = window
      let ids = if $state.epoch == $epoch {
         $state.ids
      } else {
         $links | each {|link|
            [($epoch + 1) $epoch ($epoch - 1)] | each {|at| { id: (hmac $secret $"($at) ($link.publicKey)"), link: $link } }
         } | flatten
      }
      let state = $state | merge { epoch: $epoch, ids: $ids }

      let link = $ids | where id == $shout.id | get --optional 0.link
      if $link == null { return $state }
      if ($state.heard | any {|entry| $entry.peer == $link.peer and $entry.address == $shout.address and $now - $entry.time < 4_000_000_000 }) { return $state }

      let state = if $now - $state.scanned < 5_000_000_000 {
         $state
      } else {
         let found = try { subnets } catch {|error| print --stderr $"subnet lookup failed: ($error.msg)"; [] }
         $state | merge { subnets: $found, scanned: $now }
      }
      if not (onlink $state.subnets $shout.address) { return $state }
      if (hmac $secret $"($shout.id) ($shout.address) ($shout.time) ($shout.medium)") != $shout.seal { return $state }
      if ($state.banned | any {|ban| $ban.peer == $link.peer and $ban.address == $shout.address and $ban.until > $now }) { return $state }

      let heard = $state.heard
         | where {|entry| $now - $entry.time < 15_000_000_000 and not ($entry.peer == $link.peer and $entry.address == $shout.address) }
         | append { peer: $link.peer, address: $shout.address, wired: ($shout.medium == "wired"), time: $now }
      let state = $state | update heard $heard

      let recent = $heard | where peer == $link.peer
      if $shout.medium == "wireless" and ($recent | any {|entry| $entry.wired }) { return $state }
      if ($state.trials | any {|trial| $trial.link.name == $link.name }) { return $state }

      try {
         let device = device $link $utun
         let want = $"($shout.address):($link.port)"
         let current = ^wg show $device endpoints | parse "{peer}\t{endpoint}" | get --optional 0.endpoint | default "(none)"
         if $current == $want { return $state }

         let handshake = ^wg show $device latest-handshakes | parse "{peer}\t{time}" | get --optional 0.time | default "0" | into int
         let stale = ($now // 1_000_000_000 - $handshake) >= 180
         let shouting = $recent | where {|entry| $current == $"($entry.address):($link.port)" }
         let upgrade = $shout.medium == "wired" and not ($shouting | any {|entry| $entry.wired })
         if not ($stale or ($shouting | is-empty) or $upgrade) { return $state }

         repoint $device $link $want
         print $"($link.peer) is at ($want)"
         $state | update trials { append { link: $link, address: $shout.address, previous: $current, at: $now } }
      } catch {
         $state
      }
   }
}

# A link still aimed at the last LAN would leak this host's unique port to the
# next one, so it's parked on loopback once its session goes stale. A move
# resets the handshake to 0, so a link that never answered gets 3 minutes.
def park [links: list, utun: bool] {
   mut since = {}

   loop {
      let now = date now | into int

      for link in $links {
         try {
            let device = device $link $utun
            let current = ^wg show $device endpoints | parse "{peer}\t{endpoint}" | get --optional 0.endpoint | default "(none)"
            let handshake = ^wg show $device latest-handshakes | parse "{peer}\t{time}" | get --optional 0.time | default "0" | into int
            let live = ($now // 1_000_000_000 - $handshake) < 180

            if $live or $current == "(none)" or $current == "127.0.0.1:9" {
               $since = $since | reject --optional $link.name
            } else if $handshake != 0 {
               ^wg set $device peer $link.publicKey endpoint 127.0.0.1:9
               print $"($link.peer) went quiet, parked"
            } else if ($since | get --optional $link.name | get --optional endpoint) != $current {
               $since = $since | upsert $link.name { endpoint: $current, at: $now }
            } else if $now - ($since | get $link.name | get at) >= 180_000_000_000 {
               ^wg set $device peer $link.publicKey endpoint 127.0.0.1:9
               print $"($link.peer) went quiet, parked"
            }
         }
      }

      sleep 30sec
   }
}

# settle only runs when a datagram arrives, so a quiet LAN gets one every 5s.
def tick [port: int] {
   loop {
      try { "tick\n" | ^socat -u STDIN $"UDP4-DATAGRAM:127.0.0.1:($port)" }
      sleep 5sec
   }
}

def main [links: path, port: int, key: string, secretFile: path, --send, --receive, --utun] {
   let lan = open $links | where kind == "lan"
   let dialed = $lan | where dials and endpoint == null
   let secret = open --raw $secretFile | str trim

   let parked = $lan | where endpoint == null

   if $send { job spawn { send $port $key $secret } }

   if $receive {
      job spawn { tick $port }
      job spawn { park $parked $utun }
      receive $dialed $port $secret $utun
   } else {
      park $parked $utun
   }
}
