{
   config,
   lib,
   pkgs,
   ...
}:
let
   inherit (lib)
      attrNames
      concatStringsSep
      elem
      filterAttrs
      getExe
      mkIf
      mkMerge
      ;

   cfg = config.rete;
   nu = "${getExe pkgs.nushell} --no-config-file";
   learnedLinks = filterAttrs (_: link: link.learned) cfg.links;

   # The anchor learns a dynamic hub's address from its handshakes and serves
   # it over the overlay, so it never lands in public DNS.
   servedLinks = filterAttrs (
      _: link:
      !link.dials
      && link.kind == "wan"
      && elem link.peer cfg.hubs
      && cfg.hosts.${link.peer}.endpoint == null
   ) cfg.links;
in
{
   config = mkIf cfg.enable (mkMerge [
      (mkIf (learnedLinks != { }) {
         systemd.services.rete-endpoint = {
            description = "Point rete links at hubs' current addresses";
            after = [ "rete-links.service" ];
            path = [ pkgs.wireguard-tools ];

            serviceConfig = {
               Type = "oneshot";
               ExecStart = "${nu} ${../endpoint.nu} ${cfg.linksFile} ${cfg.anchorUrl}";
            };
         };

         systemd.timers.rete-endpoint = {
            wantedBy = [ "timers.target" ];

            timerConfig = {
               OnBootSec = "20s";
               OnUnitActiveSec = "60s";
            };
         };
      })

      (mkIf (servedLinks != { }) {
         systemd.sockets.rete-endpoints = {
            wantedBy = [ "sockets.target" ];

            socketConfig = {
               ListenStream = "[${cfg.address}]:${toString cfg.port}";
               FreeBind = true;
               Accept = true;
            };
         };

         systemd.services."rete-endpoints@" = {
            path = [ pkgs.wireguard-tools ];

            serviceConfig = {
               ExecStart = "${nu} ${./answer.nu} ${cfg.linksFile} ${concatStringsSep " " (attrNames servedLinks)}";
               StandardInput = "socket";
               StandardOutput = "socket";
            };
         };
      })
   ]);
}
