def main [--hub, --systemctl: path] {
   # Hubs forward, and a forwarding kernel ignores router advertisements unless
   # accept_ra is 2. Without this, a hub using SLAAC loses its IPv6 route.
   if $hub {
      let acceptRa = $"/proc/sys/net/ipv6/conf/($env.INTERFACE)/accept_ra"
      if ($acceptRa | path exists) and (open --raw $acceptRa | str trim) == "1" {
         "2" | save --force $acceptRa
      }
   }

   if $systemctl != null {
      ^$systemctl --no-block try-restart rete.service
   }
}
