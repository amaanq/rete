{
   config,
   lib,
   pkgs,
   ...
}:
let
   inherit (lib)
      all
      allUnique
      any
      attrNames
      attrValues
      elem
      filter
      filterAttrs
      findFirst
      listToAttrs
      mapAttrs
      mapAttrsToList
      min
      mkEnableOption
      mkOption
      nameValuePair
      remove
      stringLength
      toHexString
      toLower
      types
      ;

   cfg = config.rete;
   self = cfg.hostName;
   host = cfg.hosts.${self};
   members = filterAttrs (_: entry: entry.publicKey != null) cfg.hosts;
   isHub = elem self cfg.hubs;
   fixed = name: cfg.hosts.${name}.endpoint != null;
   hex = id: toLower (toHexString id);

   # Lower rank dials. Hubs and fixed addresses rank up because they can be
   # reached first, and ids (at most 255) break the tie.
   rank =
      name:
      (if elem name cfg.hubs then 512 else 0) + (if fixed name then 256 else 0) + cfg.hosts.${name}.id;
   dialer = peer: if rank self < rank peer then self else peer;

   # Only hubs relay, so any other peer can only send from and announce its own
   # address. Link-local and multicast carry babel itself.
   trust =
      peer:
      let
         pinned = !(elem peer cfg.hubs);
         address = cfg.addresses.${peer};
      in
      {
         inherit pinned address;
         allowedIPs =
            if pinned then
               [
                  "${address}/128"
                  "fe80::/10"
                  "ff00::/8"
               ]
            else
               [ "::/0" ];
      };

   link =
      {
         peer,
         kind,
         prefix,
         offset,
         from,
         remote,
         rxcost,
         localPort ? null,
         mtu ? min host.mtu cfg.hosts.${peer}.mtu,
      }:
      let
         port = cfg.port + offset + cfg.hosts.${from}.id;
         dials = from == self;
      in
      nameValuePair "${prefix}-${peer}" (
         {
            inherit
               peer
               kind
               port
               dials
               mtu
               rxcost
               ;
            listenPort = if dials then null else port;
            localPort = if dials then localPort else null;
            endpoint =
               if dials && remote != null then
                  "${remote}:${toString (if localPort != null then localPort else port)}"
               else
                  null;
            learned = dials && remote == null && kind == "wan";
         }
         // trust peer
      );

   wanLink =
      peer:
      link {
         inherit peer;
         kind = "wan";
         prefix = "rete";
         offset = 0;
         from = dialer peer;
         remote = cfg.hosts.${peer}.endpoint;
         rxcost = 384;
      };

   lanLink =
      peer:
      link {
         inherit peer;
         kind = "lan";
         prefix = "retel";
         offset = 10000;
         # Only the dialing side uses an address, so a lanAddress on just one
         # side has to be dialed, whatever the ranks say.
         from =
            if (host.lanAddress != null) != (cfg.hosts.${peer}.lanAddress != null) then
               (if host.lanAddress != null then peer else self)
            else
               dialer peer;
         remote = cfg.hosts.${peer}.lanAddress;
         rxcost = 128;
      };

   # The last resort, priced above a three-hop UDP path (3 * 384). The local
   # port is per hub, since a laptop runs one wstunnel client for each.
   tcpLink =
      peer:
      link {
         inherit peer;
         kind = "tcp";
         prefix = "retet";
         offset = 20000;
         from = if elem peer cfg.hubs then self else peer;
         remote = "127.0.0.1";
         localPort = cfg.port + 20000 + cfg.hosts.${peer}.id;
         mtu = 1280;
         rxcost = 2048;
      };

   tcpHubs = filter (name: cfg.hosts.${name}.tcpUrl != null) cfg.hubs;

   spokes = filter (name: !(elem name cfg.hubs)) (attrNames members);
   directs = filter fixed spokes;

   # A host with a fixed address that isn't a hub takes direct links from every
   # other host, but forwards and announces nothing beyond its own address.
   wanPeers =
      if isHub then
         remove self (attrNames members)
      else
         cfg.hubs ++ remove self (if fixed self then spokes else directs);

   # Hubs already share a WAN link, so a TCP link only joins a hub to the
   # non-hubs that want one.
   tcpPeers =
      if elem self tcpHubs then
         filter (name: cfg.hosts.${name}.tcpFallback) spokes
      else if host.tcpFallback && !isHub then
         tcpHubs
      else
         [ ];

   # Any two hosts that might share a LAN get an encrypted link when either
   # one refuses plaintext. Discovery finds the other end, so the link only
   # comes up where they do share one.
   lanPeers = filter (
      name:
      name != self
      && host.lan != "none"
      && members.${name}.lan != "none"
      && (host.lan == "encrypt" || members.${name}.lan == "encrypt")
   ) (attrNames members);

   hostType = types.submodule {
      options = {
         id = mkOption {
            type = types.ints.between 1 255;
            description = "Unique host number. It ends the overlay address and picks the port the host dials in on.";
         };

         publicKey = mkOption {
            type = types.nullOr types.str;
            default = null;
            description = "WireGuard public key. Hosts without one keep their address but get no links.";
         };

         endpoint = mkOption {
            type = types.nullOr types.str;
            default = null;
            example = "203.0.113.67";
            description = ''
               Fixed public address. Hubs without one are learned from the anchor.
               Any other host with one takes direct links from every host, without
               relaying for them.
            '';
         };

         lanAddress = mkOption {
            type = types.nullOr types.str;
            default = null;
            example = "192.168.1.67";
            description = ''
               Fixed LAN address. Encrypted LAN links always dial it and ignore
               discovery, which also reaches it from another VLAN or subnet, where
               discovery broadcasts don't travel. Hosts that dial it keep sending
               there from any network they join, so use it for servers whose
               dialers stay on that LAN.
            '';
         };

         lan = mkOption {
            type = types.enum [
               "plain"
               "encrypt"
               "none"
            ];
            default = "encrypt";
            description = ''
               What to do on whatever LAN this host is plugged into.

               - `encrypt` links it straight to each other host on the same LAN
                 over WireGuard. Hosts find each other with IPv4 broadcasts
                 on the overlay port + 10000, so IPv6-only LANs need `lanAddress`.
                 Broadcasts older than 30 seconds are dropped, so clocks have to
                 stay within that of each other.
               - `plain` runs babel on every physical NIC and talks to LAN
                 neighbours unencrypted, at full line rate. Babel's key only proves
                 a sender holds it, so every plain host on a segment can announce or
                 spoof any overlay address there. Use it only on a LAN where every
                 plain host is trusted as much as a hub.
               - `none` is for a NIC on a provider's network, like a VPS.
            '';
         };

         tcpUrl = mkOption {
            type = types.nullOr types.str;
            default = null;
            example = "wss://vps.example.com";
            description = ''
               HTTPS URL of a hub's reverse proxy, which forwards `/rete/` as a
               websocket to `rete.tcpListen` on that hub.
            '';
         };

         tcpFallback = mkOption {
            type = types.bool;
            default = false;
            description = "Also reach hubs with a `tcpUrl` over WireGuard inside a websocket, for networks that block UDP.";
         };

         mtu = mkOption {
            type = types.ints.positive;
            default = 1420;
            description = "MTU for this host's tunnels. Each link takes the lower of its two hosts' values, except TCP fallback links, which always use 1280.";
         };
      };
   };

   linkType = types.submodule {
      options = {
         peer = mkOption { type = types.str; };
         port = mkOption { type = types.port; };
         dials = mkOption { type = types.bool; };
         kind = mkOption {
            type = types.enum [
               "wan"
               "lan"
               "tcp"
            ];
         };
         listenPort = mkOption { type = types.nullOr types.port; };
         localPort = mkOption { type = types.nullOr types.port; };
         endpoint = mkOption { type = types.nullOr types.str; };
         learned = mkOption { type = types.bool; };
         mtu = mkOption { type = types.ints.positive; };
         rxcost = mkOption { type = types.ints.positive; };
         pinned = mkOption { type = types.bool; };
         allowedIPs = mkOption { type = types.listOf types.str; };
         address = mkOption { type = types.str; };
      };
   };

   readOnly =
      type: default:
      mkOption {
         inherit type default;
         readOnly = true;
      };
in
{
   options.rete = {
      enable = mkEnableOption "the rete mesh on this host" // {
         default = members ? ${self};
         defaultText = "whether this host has a public key";
      };

      hostName = mkOption {
         type = types.str;
         default = config.networking.hostName;
         defaultText = "config.networking.hostName";
      };

      prefix = mkOption {
         type = types.strMatching /* regex */ "[0-9a-f]{1,4}(:[0-9a-f]{1,4}){2}";
         example = "fd67:6767:6767";
         description = "First 48 bits of the overlay. Each host is `<prefix>::<id>`.";
      };

      hosts = mkOption {
         type = types.attrsOf hostType;
         description = "The hosts in the mesh. Set the same table on all of them, since each one works out its links from it.";
      };

      hubs = mkOption {
         type = types.listOf types.str;
         description = "Hosts that every other host links to and that relay between them.";
      };

      anchor = mkOption {
         type = types.nullOr types.str;
         default = findFirst fixed null cfg.hubs;
         defaultText = "the first hub with an endpoint";
         description = "Hub with a fixed address that tells the rest of the mesh where the hubs without one are right now.";
      };

      port = mkOption {
         type = types.ints.between 1 45280;
         default = 6767;
         description = ''
            All of rete's ports count up from this one. A link's port adds the id
            of the host that dials it, so a listener gets one port per peer.

            - WAN links use `port + id`.
            - Encrypted LAN links use `port + 10000 + id`, and discovery uses
              `port + 10000` itself.
            - TCP fallback links use `port + 20000 + id`, on loopback.
            - The hub's wstunnel server sits on `port + 20000`, on loopback.
            - The anchor serves its endpoint list on `port` itself, over TCP.
         '';
      };

      keyFile = mkOption {
         type = types.path;
         description = "This host's WireGuard private key.";
      };

      babelKeyFile = mkOption {
         type = types.path;
         description = "Hex HMAC-SHA256 key that babel signs its packets with, shared by all hosts. `openssl rand -hex 32` makes one.";
      };

      lanKeyFile = mkOption {
         type = types.nullOr types.path;
         default = null;
         description = ''
            Hex key for everything on physical NICs, which is babel on `plain`
            hosts and discovery on `encrypt` ones. It's kept apart from
            `babelKeyFile` so `lan = "none"` servers never hold a key that works on
            your LAN, and every other host needs the same one.
         '';
      };

      fwMark = mkOption {
         type = types.nullOr types.ints.unsigned;
         default = null;
         description = "Firewall mark on the tunnels' own packets, for hosts whose policy routing needs to recognise them.";
      };

      address = readOnly types.str "${cfg.prefix}::${hex host.id}";

      network = readOnly types.str "${cfg.prefix}::/48";

      addresses = readOnly (types.attrsOf types.str) (
         mapAttrs (_: entry: "${cfg.prefix}::${hex entry.id}") cfg.hosts
      );

      linkLocal = readOnly types.str "fe80::${hex host.id}";

      isHub = readOnly types.bool isHub;

      # A host with a lanAddress is always dialed there, so it never needs to
      # shout, and only links that follow discovery need to listen for shouts.
      discovery =
         let
            lan = attrValues (filterAttrs (_: link: link.kind == "lan") cfg.links);
         in
         readOnly (types.attrsOf types.bool) {
            send = host.lanAddress == null && any (link: !link.dials) lan;
            receive = any (link: link.dials && link.endpoint == null) lan;
         }
         // {
            internal = true;
         };

      tcpListen = readOnly types.str "127.0.0.1:${toString (cfg.port + 20000)}";

      anchorUrl =
         readOnly (types.nullOr types.str) (
            if cfg.anchor == null then null else "http://[${cfg.addresses.${cfg.anchor}}]:${toString cfg.port}/"
         )
         // {
            internal = true;
         };

      linksFile =
         readOnly types.path (
            pkgs.writeText "rete-links.json" (
               builtins.toJSON (
                  mapAttrsToList (name: link: {
                     inherit name;
                     inherit (link)
                        peer
                        kind
                        dials
                        port
                        rxcost
                        learned
                        pinned
                        address
                        allowedIPs
                        endpoint
                        listenPort
                        mtu
                        ;
                     inherit (cfg.hosts.${link.peer}) publicKey;
                  }) cfg.links
               )
            )
         )
         // {
            internal = true;
         };

      babelFilters =
         readOnly types.lines ''
            in ip ${cfg.network} ge 48 allow
            in deny
            out ip ${if isHub then "${cfg.network} ge 48" else "${cfg.address}/128"} allow
            out deny
            redistribute local ip ${cfg.address}/128 allow
            redistribute local deny
            redistribute deny
         ''
         // {
            internal = true;
         };

      links = readOnly (types.attrsOf linkType) (
         if cfg.enable then
            listToAttrs (map wanLink wanPeers ++ map lanLink lanPeers ++ map tcpLink tcpPeers)
         else
            { }
      );
   };

   config.assertions = [
      {
         assertion = !cfg.enable || cfg.anchor != null || all fixed cfg.hubs;
         message = "rete: a hub has no endpoint and there is no anchor to learn it from.";
      }
      {
         assertion = !cfg.enable || cfg.anchor == null || (elem cfg.anchor cfg.hubs && fixed cfg.anchor);
         message = "rete: the anchor must be a hub with an endpoint.";
      }
      {
         assertion = !cfg.enable || all (name: members ? ${name}) cfg.hubs;
         message = "rete: every hub needs a publicKey.";
      }
      {
         assertion = !cfg.enable || all (name: stringLength name <= 9) (attrNames members);
         message = "rete: host names are capped at 9 characters so retel-<name> fits the 15-character interface limit.";
      }
      {
         assertion =
            !cfg.enable
            || all (name: elem name cfg.hubs || cfg.hosts.${name}.tcpUrl == null) (attrNames cfg.hosts);
         message = "rete: only hubs can have a tcpUrl.";
      }
      {
         assertion = !cfg.enable || host.lan == "none" || cfg.lanKeyFile != null;
         message = "rete: a host whose lan isn't none needs lanKeyFile.";
      }
      {
         assertion = !cfg.enable || allUnique (mapAttrsToList (_: entry: entry.id) cfg.hosts);
         message = "rete: host ids must be unique.";
      }
   ];
}
