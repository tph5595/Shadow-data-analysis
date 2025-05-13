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
        default =
          let
            # Use Python 3.11
            python = pkgs.python311;
          in
          pkgs.mkShell {
            LD_LIBRARY_PATH = "${pkgs.stdenv.cc.cc.lib.outPath}/lib:${pkgs.lib.makeLibraryPath [pkgs.zlib]}:$LD_LIBRARY_PATH";
            # The Nix packages provided in the environment
          packages = with pkgs; 
          [ ocaml jq python3] ++
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
            ]) ++ 
          [poetry
          git-lfs
          # Python plus helper tools
          (python.withPackages (ps: with ps; [
                pip
          ]))];
        };
      });
    };
}
