{
   description = "A stateless WireGuard mesh routed by babel, configured from a Nix host table.";

   inputs = {
      nixpkgs.url = "https://channels.nixos.org/nixpkgs-unstable/nixexprs.tar.xz";

      nuff = {
         url = "github:manic-systems/nuff";
         flake = false;
      };
   };

   outputs =
      { nixpkgs, nuff, ... }:
      let
         inherit (nixpkgs) lib;
         forAllSystems = lib.genAttrs (lib.systems.doubles.linux ++ lib.systems.doubles.darwin);
         pkgsFor = system: nixpkgs.legacyPackages.${system} or (import nixpkgs { inherit system; });
      in
      {
         nixosModules.default = ./nix/nixos;
         darwinModules.default = ./nix/darwin.nix;

         formatter = forAllSystems (
            system:
            let
               pkgs = pkgsFor system;
            in
            pkgs.writeShellApplication {
               name = "nuff";
               runtimeInputs = [ pkgs.nixfmt ];
               text = ''exec ${lib.getExe (pkgs.callPackage "${nuff}/nix/package.nix" { })} "$@"'';
            }
         );
      };
}
