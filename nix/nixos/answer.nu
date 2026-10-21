def main [links: path, ...served: string] {
   ^head -n 1 | ignore

   let lines = open $links | where name in $served | each {|link|
      let endpoint = ^wg show $link.name endpoints | parse "{key}\t{endpoint}" | get --optional 0.endpoint
      if $endpoint != null and $endpoint != "(none)" {
         let address = $endpoint | str replace --regex ':\d+$' ""
         $"($link.peer) ($address)\n"
      }
   } | compact

   print --no-newline $"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\n($lines | str join)"
}
