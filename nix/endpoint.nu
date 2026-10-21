# Points learned links at the hub addresses the anchor reports. On macOS,
# --utun looks up which utun each wg-quick link got.
def main [links: path, anchor: string, --utun] {
   let answer = try {
      http get --max-time 5sec $anchor
   } catch {
      print "the anchor is unreachable, keeping the current endpoints"
      exit 0
   }
   let known = $answer | lines | parse "{peer} {address}"

   for link in (open $links | where learned) {
      let found = $known | where peer == $link.peer
      if ($found | is-empty) { continue }

      let nameFile = $"/var/run/wireguard/($link.name).name"
      if $utun and not ($nameFile | path exists) { continue }
      let device = if $utun { open --raw $nameFile | str trim } else { $link.name }

      let want = $"($found.0.address):($link.port)"
      let current = ^wg show $device endpoints | parse "{key}\t{endpoint}" | get --optional 0.endpoint
      if $current == $want { continue }

      ^wg set $device peer $link.publicKey endpoint $want
      print $"($link.peer) is at ($want)"
   }
}
