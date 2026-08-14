{ buildGoModule }:

buildGoModule {
  pname = "git-vault";
  version = "0.1.0";
  src = ./.;
  subPackages = [ "cmd/git-vault" ];

  vendorHash = "sha256-OVEvz/gs1U3KBQt3LtZqNjKHXhBqAZZBtxds+GiKEkY=";

  meta = {
    description = "Transparently encrypt secret files in a git repository";
    mainProgram = "git-vault";
  };
}
