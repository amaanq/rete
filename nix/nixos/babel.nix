{
   config,
   lib,
   pkgs,
   ...
}:
let
   inherit (lib)
      attrNames
      concatMapStrings
      concatStringsSep
      getExe
      mkIf
      optional
      optionals
      optionalString
      ;

   cfg = config.rete;
   plainLan = cfg.hosts.${cfg.hostName}.lan == "plain";
   nu = "${getExe pkgs.nushell} --no-config-file";
   interfaces = attrNames cfg.links;

   hotplug = concatStringsSep " " (
      [
         nu
         "${./hotplug.nu}"
      ]
      ++ optional cfg.isHub "--hub"
      ++ optionals plainLan [
         "--systemctl"
         "${config.systemd.package}/bin/systemctl"
      ]
   );

   babelConfig = pkgs.writeText "rete-babeld.conf" ''
      skip-kernel-setup true
      local-path /run/rete/babeld.sock
      default hello-interval 1 key rete
      ${concatMapStrings (name: ''
         interface ${name} type tunnel rxcost ${toString cfg.links.${name}.rxcost}
      '') interfaces}
      ${concatMapStrings (
         name:
         optionalString cfg.links.${name}.pinned ''
            in if ${name} ip ${cfg.links.${name}.address}/128 allow
            in if ${name} deny
         ''
      ) interfaces}
      ${cfg.babelFilters}
   '';
in
{
   config = mkIf cfg.enable {
      boot.kernel.sysctl."net.ipv6.conf.all.forwarding" = mkIf cfg.isHub 1;

      services.udev.extraRules = mkIf (cfg.isHub || plainLan) /* udev */ ''
         ACTION=="add", SUBSYSTEM=="net", DEVPATH!="/devices/virtual/*", RUN+="${hotplug}"
      '';

      # Not services.babeld, which turns on IPv4 forwarding and turns off
      # rp_filter on every host for an overlay that is IPv6 only.
      systemd.services.rete = {
         description = "rete babel routing";
         after = [
            "rete-address.service"
            "rete-links.service"
         ];
         wants = [
            "rete-address.service"
            "rete-links.service"
         ];
         wantedBy = [ "multi-user.target" ];
         restartTriggers = [ cfg.babelKeyFile ] ++ optional plainLan cfg.lanKeyFile;
         path = [ pkgs.babeld ];

         serviceConfig = {
            ExecStart = "${nu} ${./babeld.nu} ${babelConfig}${optionalString plainLan " --plain-lan"}";
            LoadCredential = [
               "rete:${toString cfg.babelKeyFile}"
            ]
            ++ optional plainLan "lan:${toString cfg.lanKeyFile}";
            Restart = "on-failure";

            DynamicUser = true;
            RuntimeDirectory = "rete";
            StateDirectory = "rete";
            UMask = "0177";
            AmbientCapabilities = [ "CAP_NET_ADMIN" ];
            CapabilityBoundingSet = [ "CAP_NET_ADMIN" ];
            PrivateUsers = false;
            IPAddressAllow = [
               "fe80::/64"
               "ff00::/8"
               "::1/128"
            ];
            IPAddressDeny = "any";
            RestrictAddressFamilies = [
               "AF_NETLINK"
               "AF_INET"
               "AF_INET6"
               "AF_UNIX"
            ];
            DevicePolicy = "closed";
            LockPersonality = true;
            MemoryDenyWriteExecute = true;
            NoNewPrivileges = true;
            PrivateDevices = true;
            PrivateMounts = true;
            PrivateTmp = true;
            ProcSubset = "pid";
            ProtectClock = true;
            ProtectControlGroups = true;
            ProtectHome = true;
            ProtectHostname = true;
            ProtectKernelLogs = true;
            ProtectKernelModules = true;
            ProtectKernelTunables = true;
            ProtectProc = "invisible";
            ProtectSystem = "strict";
            RemoveIPC = true;
            RestrictNamespaces = true;
            RestrictRealtime = true;
            RestrictSUIDSGID = true;
            SystemCallArchitectures = "native";
            SystemCallFilter = [
               "@system-service"
               "~@privileged"
            ];
         };
      };
   };
}
