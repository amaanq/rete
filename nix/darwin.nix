{
   config,
   lib,
   pkgs,
   ...
}:
let
   inherit (lib)
      filterAttrs
      getExe
      mapAttrs
      mapAttrs'
      mkForce
      mkIf
      mkMerge
      nameValuePair
      optional
      optionals
      ;

   cfg = config.rete;
   host = cfg.hosts.${cfg.hostName};
   nu = "${getExe pkgs.nushell} --no-config-file";
   plainLan = host.lan == "plain";

   # Every SIOCGIFMTU leaks a socket, and at launchd's 256 fd limit babeld goes silent.
   babeld = pkgs.babeld.overrideAttrs (old: {
      patches = old.patches or [ ] ++ [
         ./babeld-mtu-socket-leak.patch
         ./babeld-quiet-endpointless-peer.patch
      ];
   });

   learnedLinks = filterAttrs (_: link: link.learned) cfg.links;
   tcpLinks = filterAttrs (_: link: link.kind == "tcp") cfg.links;
   lanLinks = filterAttrs (_: link: link.kind == "lan") cfg.links;

   # By default, babeld turns on IPv6 forwarding. macOS ignores router
   # advertisements while forwarding, so the Mac would lose its IPv6 route.
   babelConfig = pkgs.writeText "rete-babeld.conf" ''
      skip-kernel-setup true
      local-path /var/run/rete-babeld.sock
      default hello-interval 1 key rete
      ${cfg.babelFilters}
   '';
in
{
   imports = [ ./options.nix ];

   config = mkIf cfg.enable (mkMerge [
      {
         assertions = [
            {
               assertion = !cfg.isHub;
               message = "rete: a macOS host cannot be a hub, it neither forwards nor relays routes.";
            }
         ];

         networking.wg-quick.interfaces = mapAttrs (_: link: {
            address = [ "${cfg.address}/128" ];
            inherit (link) listenPort mtu;
            privateKeyFile = toString cfg.keyFile;
            table = "off";

            peers = [
               {
                  inherit (cfg.hosts.${link.peer}) publicKey;
                  inherit (link) allowedIPs;
                  inherit (link) endpoint;
                  persistentKeepalive = if link.dials then 25 else null;
               }
            ];
         }) cfg.links;

         # nix-darwin only relaunches wg-quick after a successful exit.
         launchd.daemons = mapAttrs' (
            name: _:
            nameValuePair "wg-quick-${name}" {
               serviceConfig = {
                  KeepAlive = mkForce {
                     SuccessfulExit = false;
                  };
                  ThrottleInterval = 10;
               };
            }
         ) cfg.links;
      }

      {
         launchd.daemons.rete = {
            path = [
               babeld
               "/usr/bin"
               "/usr/sbin"
               "/sbin"
            ];

            serviceConfig = {
               ProgramArguments = [
                  (getExe pkgs.nushell)
                  "--no-config-file"
                  "${./darwin-babeld.nu}"
                  "${cfg.linksFile}"
                  "${babelConfig}"
                  (toString cfg.babelKeyFile)
                  cfg.address
               ]
               ++ optionals plainLan [
                  "--plain-lan"
                  "--lan-key"
                  (toString cfg.lanKeyFile)
               ];
               RunAtLoad = true;
               KeepAlive = true;
               ThrottleInterval = 10;
            };
         };

         # A restarted link can come back on a different utun, and babeld only
         # reads interface names at startup, so restart it whenever one changes.
         launchd.daemons.rete-relink.serviceConfig = {
            ProgramArguments = [
               "/bin/launchctl"
               "kickstart"
               "-k"
               "system/${config.launchd.daemons.rete.serviceConfig.Label}"
            ];
            WatchPaths = [ "/var/run/wireguard" ];
         };
      }

      {
         launchd.daemons = mapAttrs' (
            _: link:
            nameValuePair "rete-wstunnel-${link.peer}" {
               serviceConfig = {
                  ProgramArguments = [
                     (getExe pkgs.wstunnel)
                     "client"
                     "--http-upgrade-path-prefix"
                     "rete"
                     "-L"
                     "udp://127.0.0.1:${toString link.localPort}:127.0.0.1:${toString link.port}?timeout_sec=0"
                     cfg.hosts.${link.peer}.tcpUrl
                  ];
                  RunAtLoad = true;
                  KeepAlive = true;
                  ThrottleInterval = 10;
               };
            }
         ) (filterAttrs (_: link: link.dials) tcpLinks);
      }

      (mkIf (lanLinks != { }) {
         launchd.daemons.rete-discover = {
            path = [
               pkgs.socat
               pkgs.wireguard-tools
               "/usr/sbin"
               "/sbin"
            ];

            serviceConfig = {
               ProgramArguments = [
                  (getExe pkgs.nushell)
                  "--no-config-file"
                  "${./discover.nu}"
                  "${cfg.linksFile}"
                  (toString (cfg.port + 10000))
                  host.publicKey
                  (toString cfg.lanKeyFile)
                  "--utun"
               ]
               ++ optional cfg.discovery.send "--send"
               ++ optional cfg.discovery.receive "--receive";
               RunAtLoad = true;
               KeepAlive = true;
               ThrottleInterval = 10;
            };
         };
      })

      (mkIf (learnedLinks != { }) {
         launchd.daemons.rete-endpoint = {
            command = "${nu} ${./endpoint.nu} ${cfg.linksFile} ${cfg.anchorUrl} --utun";
            path = [ pkgs.wireguard-tools ];

            serviceConfig = {
               RunAtLoad = true;
               StartInterval = 60;
            };
         };
      })
   ]);
}
