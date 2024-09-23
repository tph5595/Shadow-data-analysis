{
  description = "A Nix-flake-based OCaml development environment";

  inputs.nixpkgs.url = "https://flakehub.com/f/NixOS/nixpkgs/*.tar.gz";

  outputs = { self, nixpkgs }:
    let
      supportedSystems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forEachSupportedSystem = f: nixpkgs.lib.genAttrs supportedSystems (system: f {
        pkgs = import nixpkgs { inherit system; };
      });
    in
    {
      devShells = forEachSupportedSystem ({ pkgs }: {
        default = pkgs.mkShell {
          packages = with pkgs; 
          [ ocaml ] ++
            (with pkgs.ocamlPackages; [ 
            dune_3 
            odoc 
            utop 
            fmt 
            core 
            core_unix 
            base 
            batteries 
            findlib
            ocaml_pcre
            yojson
            ]);
        };
      });
    };
}
