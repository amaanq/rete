def main [config: path, --plain-lan] {
   let ids = if $plain_lan { [rete lan] } else { [rete] }
   $ids
   | each {|id|
      let key = open --raw $"($env.CREDENTIALS_DIRECTORY)/($id)" | str trim
      $"key id ($id) type hmac-sha256 value ($key)\n"
   }
   | str join
   | save --force /run/rete/key.conf

   # Babel on every physical NIC finds LAN neighbours without any location
   # config. udev restarts babel when a new NIC shows up.
   let lan = if $plain_lan {
      ls /sys/class/net
      | get name
      | where {|dev| $dev | path join device | path exists }
      | each {|dev|
         let type = if ($dev | path join wireless | path exists) { "wireless" } else { "wired" }
         $"interface ($dev | path basename) type ($type) key lan\n"
      }
      | str join
      | save --force /run/rete/lan.conf

      [-c /run/rete/lan.conf]
   } else {
      []
   }

   exec babeld -c /run/rete/key.conf -c $config ...$lan -I /run/rete/babeld.pid -S /var/lib/rete/babeld-state
}
