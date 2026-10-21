# macOS only sends a packet out an interface that holds its source address,
# so every candidate NIC gets the overlay address.
def main [links: path, config: path, key: path, address: string, --plain-lan, --lan-key: path] {
   let links = open $links

   for link in $links {
      mut tries = 0
      while not ($"/var/run/wireguard/($link.name).name" | path exists) and $tries < 60 {
         sleep 1sec
         $tries += 1
      }
   }

   # rete-relink restarts babel once a late link's name file appears.
   let links = $links | where {|link| $"/var/run/wireguard/($link.name).name" | path exists }

   ^install -m 600 /dev/null /var/run/rete-babeld.conf
   let secret  = open --raw $key | str trim
   let lanKeys = if $lan_key != null {
      [$"key id lan type hmac-sha256 value (open --raw $lan_key | str trim)\n"]
   } else {
      []
   }
   let nicKey = if $lan_key != null { " key lan" } else { "" }
   let links   = $links | insert utun {|link| open --raw $"/var/run/wireguard/($link.name).name" | str trim }
   let tunnels = $links | each {|link| $"interface ($link.utun) type tunnel rxcost ($link.rxcost)\n" }
   let pins    = $links | where pinned | each {|link|
      $"in if ($link.utun) ip ($link.address)/128 allow\nin if ($link.utun) deny\n"
   }

   let ports = ^networksetup -listallhardwareports
      | split row "\n\n"
      | where {|block| $block =~ "Device: en" }
      | each {|block| $block | lines | parse "{field}: {value}" | transpose --header-row --as-record }
   let lan = $ports | where {|port| $plain_lan and not ($port."Hardware Port" starts-with "Thunderbolt") }

   for port in $ports {
      try { ^ifconfig $port.Device inet6 $address delete } catch { }
   }

   # Wired and Wi-Fi on one LAN otherwise flag the shared address duplicated.
   let nics = $lan | each {|port|
      try { ^ifconfig $port.Device inet6 -dad }
      try { ^ifconfig $port.Device inet6 $address prefixlen 128 alias }
      let type = if ($port."Hardware Port" =~ "Wi-Fi") { "wireless" } else { "wired" }
      $"interface ($port.Device) type ($type)($nicKey)\n"
   }

   let babelConfig = [
      $"key id rete type hmac-sha256 value ($secret)\n"
      ...$lanKeys
      ...$pins
      (open --raw $config)
      ...$tunnels
      ...$nics
   ]

   $babelConfig | str join | save --force /var/run/rete-babeld.conf

   exec babeld -c /var/run/rete-babeld.conf -I /var/run/rete-babeld.pid -S /var/db/rete-babeld-state
}
