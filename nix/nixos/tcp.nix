{ config, lib, ... }:
let
   inherit (lib)
      filterAttrs
      mapAttrs'
      mapAttrsToList
      mkIf
      mkMerge
      nameValuePair
      ;

   cfg = config.rete;
   tcpLinks = filterAttrs (_: link: link.kind == "tcp") cfg.links;
   dialed = filterAttrs (_: link: link.dials) tcpLinks;
   served = filterAttrs (_: link: !link.dials) tcpLinks;
in
{
   config = mkIf cfg.enable (mkMerge [
      (mkIf (served != { }) {
         services.wstunnel = {
            enable = true;

            servers.rete = {
               listen = {
                  host = "127.0.0.1";
                  port = cfg.port + 20000;
                  enableHTTPS = false;
               };

               settings = {
                  restrict-to = mapAttrsToList (_: link: {
                     host = "127.0.0.1";
                     inherit (link) port;
                  }) served;
                  restrict-http-upgrade-path-prefix = "rete";
               };
            };
         };
      })

      (mkIf (dialed != { }) {
         services.wstunnel = {
            enable = true;

            clients = mapAttrs' (
               _: link:
               nameValuePair "rete-${link.peer}" {
                  connectTo = cfg.hosts.${link.peer}.tcpUrl;

                  settings = {
                     local-to-remote = [
                        "udp://127.0.0.1:${toString link.localPort}:127.0.0.1:${toString link.port}?timeout_sec=0"
                     ];
                     http-upgrade-path-prefix = "rete";
                  };
               }
            ) dialed;
         };
      })
   ]);
}
