# Discovery and the anchor repoint endpoints at runtime, so a reload only sets
# the configured endpoint on a peer that has none.
def main [links: path, key: path, address: string, fwmark?: string] {
   let wanted = open $links
   let present = ^ip -json link show type wireguard | from json | get ifname | where ($it | str starts-with "rete-")

   for stale in ($present | where $it not-in $wanted.name) {
      ^ip link delete $stale
      print $"removed ($stale)"
   }

   let failed = $wanted | each {|link|
      if $link.name not-in $present {
         ^ip link add $link.name type wireguard
      }

      let port = if $link.listenPort == null { [] } else { [listen-port $link.listenPort] }
      let mark = if $fwmark == null { [] } else { [fwmark $fwmark] }
      ^wg set $link.name private-key $key ...$port ...$mark

      for peer in (^wg show $link.name peers | lines | where $it != $link.publicKey) {
         ^wg set $link.name peer $peer remove
      }

      let keepalive = if $link.dials { 25 } else { 0 }
      (^wg set $link.name peer $link.publicKey
         allowed-ips ($link.allowedIPs | str join ",") persistent-keepalive $keepalive)

      ^ip -6 address replace $"($address)/64" dev $link.name
      ^ip link set $link.name mtu $link.mtu up

      let current = ^wg show $link.name endpoints | parse "{peer}\t{endpoint}" | get --optional 0.endpoint
      if $link.endpoint == null or $current != "(none)" { return }

      # A hostname endpoint can fail to resolve this early in boot. The link
      # still comes up, and the unit fails so systemd retries it.
      let result = ^wg set $link.name peer $link.publicKey endpoint $link.endpoint | complete
      if $result.exit_code == 0 { return }

      print $"($link.name): ($result.stderr | str trim)"
      $link.name
   } | compact

   if ($failed | is-not-empty) { exit 1 }
}
