{
   config,
   lib,
   pkgs,
   ...
}:
let
   inherit (lib)
      attrNames
      attrValues
      catAttrs
      concatStringsSep
      filterAttrs
      getExe
      getExe'
      mkIf
      optional
      remove
      ;

   cfg = config.rete;
   plainLan = cfg.hosts.${cfg.hostName}.lan == "plain";
   ip = getExe' pkgs.iproute2 "ip";
   udpLinks = filterAttrs (_: link: link.kind != "tcp") cfg.links;
in
{
   imports = [
      ../options.nix
      ./babel.nix
      ./discover.nix
      ./endpoints.nix
      ./tcp.nix
   ];

   config = mkIf cfg.enable {
      systemd.services.rete-address = {
         description = "rete0 interface holding the overlay address";
         wantedBy = [ "network.target" ];
         before = [ "network.target" ];
         after = [ "network-pre.target" ];

         serviceConfig = {
            Type = "oneshot";
            RemainAfterExit = true;
            ExecStart = [
               "-${ip} link add rete0 type dummy"
               "${ip} -6 address replace ${cfg.address}/128 dev rete0"
               "${ip} link set rete0 up"
            ];
            ExecStop = "${ip} link delete rete0";
         };
      };

      boot.kernelModules = [ "wireguard" ];

      systemd.services.rete-links =
         let
            links = concatStringsSep " " (
               [
                  "${getExe pkgs.nushell} --no-config-file ${./links.nu}"
                  "${cfg.linksFile}"
                  (toString cfg.keyFile)
                  cfg.linkLocal
               ]
               ++ optional (cfg.fwMark != null) (toString cfg.fwMark)
            );
         in
         {
            description = "rete WireGuard links";
            wantedBy = [ "multi-user.target" ];
            before = [ "network.target" ];
            wants = [ "network.target" ];
            after = [ "network-pre.target" ];
            restartIfChanged = false;
            reloadTriggers = [ cfg.linksFile ];
            path = [
               pkgs.iproute2
               pkgs.wireguard-tools
            ];

            serviceConfig = {
               Type = "oneshot";
               RemainAfterExit = true;
               Restart = "on-failure";
               RestartSec = "10s";
               ExecStart = links;
               ExecReload = links;
               ExecStop = map (name: "-${ip} link delete ${name}") (attrNames cfg.links);
            };
         };

      networking.firewall = {
         trustedInterfaces = attrNames cfg.links;
         allowedUDPPorts =
            remove null (catAttrs "listenPort" (attrValues udpLinks)) ++ optional plainLan 6696;

         # Let plain LAN neighbours in, but only on the NIC babel routes them
         # through. NixOS's own reverse-path check is loose, so it won't.
         extraInputRules = mkIf (plainLan && config.networking.nftables.enable) ''
            ip6 saddr ${cfg.network} fib saddr . iif oif exists accept
         '';

         # The rpfilter match only loads in raw and mangle, so the strict check
         # drops in raw and the filter table accepts whatever survives it.
         extraCommands = mkIf (plainLan && !config.networking.nftables.enable) ''
            ip6tables -t raw -D PREROUTING -s ${cfg.network} ! -i rete-+ -m rpfilter --invert -j DROP 2>/dev/null || true
            ip6tables -t raw -A PREROUTING -s ${cfg.network} ! -i rete-+ -m rpfilter --invert -j DROP
            ip6tables -A nixos-fw -s ${cfg.network} -j nixos-fw-accept
         '';

         extraStopCommands = mkIf (plainLan && !config.networking.nftables.enable) ''
            ip6tables -t raw -D PREROUTING -s ${cfg.network} ! -i rete-+ -m rpfilter --invert -j DROP 2>/dev/null || true
         '';
      };
   };
}
