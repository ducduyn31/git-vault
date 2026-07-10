{
  description = "git-vault CLI";

  inputs = {
    # Pinned to a specific nixpkgs commit (not the "nixos-unstable" branch)
    # because at the time of writing nixos-unstable's default `go` is still
    # 1.26.4, while go.mod requires >= 1.26.5. This commit is the first on
    # the (pre-merge) "staging" branch to bump go_1_26 to 1.26.5. Once that
    # bump lands on nixos-unstable, this can be repointed back to
    # "github:NixOS/nixpkgs/nixos-unstable".
    nixpkgs.url = "github:NixOS/nixpkgs/97b993b6dec7c4e91fceabbcecff9b3cd84160a7";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
      in
      {
        # Uses nixpkgs' default Go toolchain rather than pinning an exact
        # version. go.mod requires >= 1.26.5 (latest stable at time of
        # writing) — if this nixpkgs revision's default `go` is an older
        # patch of 1.26.x, `nix build`/`nix develop` will fail needing a
        # newer toolchain; bump the `nixpkgs` input above to a revision
        # that ships >= 1.26.5 rather than pinning an exact Go derivation
        # here (keeps golangci-lint/goreleaser on current versions too).
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
