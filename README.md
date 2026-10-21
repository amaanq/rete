# rete

A WireGuard mesh for NixOS and nix-darwin hosts, routed by
[babel](https://www.irif.fr/~jch/software/babel/) and configured from one host
table.

The mesh lives entirely in your Nix config. There's no coordination server and
no database of nodes and keys to lose, so you can wipe a host, redeploy it, and
it'll come back with the same address and routes.

The host table, `rete.hosts`, is an attrset you share across every host's
config, mapping each host to an id, its WireGuard public key, and for hubs, an
optional fixed endpoint. The id picks the host's address and the ports its links
use, and the `hubs` list decides who links to whom. Adding a host means adding an
entry and redeploying it along with the hubs.

## How it works

- Every host gets `<prefix>::<id>` on a dummy interface.
- Hubs link to every host and relay between them. A host with a fixed
  `endpoint` that isn't a hub takes direct links from every host but relays
  nothing. Everyone else dials the hubs and those direct hosts.
- babel prefers a shared LAN, then a direct tunnel, then a relay through a hub,
  and moves to the next path within a few seconds when one dies.
- A hub on a dynamic address dials a hub with a fixed one, the anchor. The
  anchor serves that address to the rest of the mesh over the overlay, so it
  never has to go in public DNS.

## LAN traffic

Each host's `lan` option decides what happens on whatever network it's plugged
into.

- `encrypt` is the default. Each host gets a direct WireGuard link to every
  other host it might share a LAN with, and finds the other end through IPv4
  broadcasts on `port + 10000`, whose id rotates every 10 minutes so the
  public key never goes out on the LAN. Broadcasts more than 30 seconds old are
  dropped, so a host whose clock drifts further than that quietly stops finding
  LAN peers and falls back to WAN. Set `lanAddress` to reach a host across
  VLANs or on an IPv6-only LAN, as long as its dialers stay on that LAN.
  They keep sending to it from any network they join.
- `plain` runs babel on every physical NIC and talks to LAN neighbours
  unencrypted, at full line rate. babel's HMAC only proves a sender holds the
  key, so every plain host on a segment can announce or spoof any overlay
  address there. Use it on a LAN where you'd trust every plain host as much as
  a hub.
- `none` is for hosts whose NIC faces a provider network, like a VPS.

## Usage

```nix
# in every host's NixOS or nix-darwin config
imports = [ inputs.rete.nixosModules.default ]; # or darwinModules.default

rete = {
   prefix = "fd67:6767:6767";
   hubs   = [ "home" "vps" ];
   hosts  = {
      home   = { id = 6;  publicKey = "..."; };
      vps    = { id = 7;  publicKey = "..."; endpoint = "203.0.113.67"; lan = "none"; };
      laptop = { id = 67; publicKey = "..."; };
   };
   keyFile      = config.age.secrets.reteKey.path;
   babelKeyFile = config.age.secrets.reteBabelKey.path;
   lanKeyFile   = config.age.secrets.reteLanKey.path; # unless lan = "none"
};
```

A hub without an `endpoint` needs UDP `port + id` forwarded to it for the id of
every host that dials it. `config.rete.links` lists each link with its port, so
the router's port forwards can come from the same Nix config.

## Networks that block UDP

A host with `tcpFallback` also links to every hub that has a `tcpUrl`, with
WireGuard carried in a websocket by [wstunnel](https://github.com/erebe/wstunnel).
babel only routes over it when every UDP path is gone. The hub runs the wstunnel
server on `config.rete.tcpListen`, and its HTTPS reverse proxy forwards `/rete/`
there as a websocket.

## License

EUPL-1.2
