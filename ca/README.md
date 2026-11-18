# Optional build-time CA bundle

**Language:** English | [日本語](README_JA.md)

If your build host sits behind a TLS-inspecting proxy, or allows only TCP 443
egress (so plain-HTTP Debian mirrors are unreachable), place a combined CA
bundle named `combined-ca-bundle.pem` (system roots + the proxy's CA) in this
directory — or point the `ANTIGENT_CA_CONTEXT` build variable at a directory
that contains it. The image build then uses HTTPS Debian mirrors and this
bundle for TLS **verification** of apt and the tool downloads (verification is
never disabled). The defense image also adds it to its CA store, so the defender's
model calls work behind the same proxy; the Attack Box takes it at run time through
`CA_BUNDLE_PATH` (see `examples/attacker/.env.example`). The Attack Box sample uses the same convention through
`ATTACKER_CA_CONTEXT`, including for its pinned scanner downloads.

With an unmodified checkout this directory only holds this file, so the named
build context has no bundle and the build uses the image's system roots.
