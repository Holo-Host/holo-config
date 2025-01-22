{
  description = "Template for Holochain app development";

  inputs = {
    holochain-flake.url = "github:holochain/holochain";

    nixpkgs.follows = "holochain-flake/nixpkgs";
    flake-parts.follows = "holochain-flake/flake-parts";
  };

  outputs = inputs:
    inputs.flake-parts.lib.mkFlake { inherit inputs; } {
      systems = builtins.attrNames inputs.holochain-flake.devShells;

      perSystem = { inputs', config, pkgs, system, ... }: {
        formatter = pkgs.nixfmt-rfc-style;

        devShells.default = pkgs.mkShell {
          inputsFrom = [ inputs'.holochain-flake.devShells.rustDev ];
          packages = [
            pkgs.nodejs-18_x
            pkgs.binaryen
            pkgs.cargo-machete
            # more packages go here
          ];
        };
      };
    };
}
