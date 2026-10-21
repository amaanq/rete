{
   config,
   lib,
   pkgs,
   ...
}:
let
   inherit (lib)
      concatStringsSep
      filterAttrs
      getExe
      mkIf
      optional
      ;

   cfg = config.rete;
   lanLinks = filterAttrs (_: link: link.kind == "lan") cfg.links;
   port = cfg.port + 10000;
in
{
   config = mkIf (cfg.enable && lanLinks != { }) {
      networking.firewall.allowedUDPPorts = optional cfg.discovery.receive port;

      systemd.services.rete-discover = {
         description = "rete LAN peer discovery";
         after = [ "rete-links.service" ];
         wantedBy = [ "multi-user.target" ];
         restartTriggers = [ cfg.lanKeyFile ];
         path = [
            pkgs.iproute2
            pkgs.socat
            pkgs.wireguard-tools
         ];

         serviceConfig = {
            ExecStart = concatStringsSep " " (
               [
                  (getExe pkgs.nushell)
                  "--no-config-file"
                  "${../discover.nu}"
                  "${cfg.linksFile}"
                  (toString port)
                  cfg.hosts.${cfg.hostName}.publicKey
                  "%d/secret"
               ]
               ++ optional cfg.discovery.send "--send"
               ++ optional cfg.discovery.receive "--receive"
            );
            LoadCredential = "secret:${toString cfg.lanKeyFile}";
            Restart = "always";

            DynamicUser = true;
            AmbientCapabilities = [ "CAP_NET_ADMIN" ];
            CapabilityBoundingSet = [ "CAP_NET_ADMIN" ];
            PrivateUsers = false;
            RestrictAddressFamilies = [
               "AF_NETLINK"
               "AF_INET"
               "AF_INET6"
               "AF_UNIX"
            ];
            LockPersonality = true;
            NoNewPrivileges = true;
            PrivateDevices = true;
            PrivateTmp = true;
            ProtectHome = true;
            ProtectKernelModules = true;
            ProtectSystem = "strict";
            RestrictNamespaces = true;
            SystemCallArchitectures = "native";
         };
      };
   };
}
