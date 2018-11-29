{ pkgs ? (import <nixpkgs> {}) }:

pkgs.stdenv.mkDerivation {
  name = "nix-fetch";

  buildInputs = with pkgs; [
    pkgconfig cmake
    nix.dev boost
  ];
}

