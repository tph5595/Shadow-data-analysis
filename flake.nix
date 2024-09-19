{
  description = "Example Python development environment for Zero to Nix";

  # Flake inputs
  inputs = {
    nixpkgs.url = "https://flakehub.com/f/NixOS/nixpkgs/*.tar.gz";
  };

  # Flake outputs
  outputs = { self, nixpkgs }:
    let
      # Systems supported
      allSystems = [
        "x86_64-linux" # 64-bit Intel/AMD Linux
        "aarch64-linux" # 64-bit ARM Linux
        "x86_64-darwin" # 64-bit Intel macOS
        "aarch64-darwin" # 64-bit ARM macOS
      ];

      # Helper to provide system-specific attributes
      forAllSystems = f: nixpkgs.lib.genAttrs allSystems (system: f {
        pkgs = import nixpkgs { inherit system; };
      });
    in
    {
      # Development environment output
      devShells = forAllSystems ({ pkgs }: {
        default =
          let
            # Use Python 3.11
            python = pkgs.python311;
          in
          pkgs.mkShell {
            LD_LIBRARY_PATH = "${pkgs.stdenv.cc.cc.lib.outPath}/lib:${pkgs.lib.makeLibraryPath [pkgs.zlib]}:$LD_LIBRARY_PATH";
            # The Nix packages provided in the environment
            packages = with pkgs; [
                poetry
                git-lfs
              # Python plus helper tools
              (python.withPackages (ps: with ps; [
                pip
              ]))
            ];
          };
      });
    };
}
