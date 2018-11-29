# Nix-fetch: nix tool to download verified application bundles

nix-fetch is a utility that downloads binary derivation outputs from a
list of binary caches.

It differs from `nix copy` and `nix copy-closure` by verifying that
the entire closure is signed and that all requisite paths are from the
same set of binary caches. This allows derivations with different
trust levels to be present in the nix store.

For example, suppose you have binary caches A and B, which contain
derivations for two particular output paths, and a binary cache S,
containing derivations shared between the two. In this example, S can
represent the highly trusted binary cache of an OS distributor, and A
and B the less trusted binary caches of individual application
developers.

`nix-fetch` can fetch an application output from A while ensuring that
system paths (i.e., paths that are present in S) are copied with the
required signatures from S and that no path from A can depend on paths
from B. This prevents a malicious actor from injecting dependencies
into A's applications by serving them through B, and vice versa.

Thus, once `nix-fetch` has fetched a derivation, you can be sure that
each output derivation and its requisites are fully verified.

`nix-fetch` also distinguishes between system packages and application
packages. System packages are any packages downloaded from a system
binary cache. A system package can never depend on an application
package.


