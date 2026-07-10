{
  description = "git-vault CLI";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
      in
      {
        # Uses nixpkgs' default Go toolchain (currently satisfies go.mod's
        # >= 1.26.4 floor) rather than pinning an exact Go derivation.
        packages.default = pkgs.buildGoModule {
          pname = "git-vault";
          version = "0.1.0";
          src = ./.;
          subPackages = [ "cmd/git-vault" ];

          vendorHash = "sha256-8L9t2ub9khVqrk9MCSZ/lYWXJxRQFUdP2Hi9lRX3mIc=";

          meta = {
            description = "Transparently encrypt secret files in a git repository";
            mainProgram = "git-vault";
          };
        };

        devShells.default = pkgs.mkShell {
          buildInputs = [
            pkgs.go
            pkgs.golangci-lint
            pkgs.goreleaser
            pkgs.gofumpt
            pkgs.go-task
          ];
        };
      });
}
