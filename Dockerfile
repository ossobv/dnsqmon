# Multi-stage build for a tiny DaemonSet image.
#
# We build against musl so the final binary is statically linked and can run
# in a distroless/scratch container. libpcap itself is linked statically.
#
# GIT_VERSION is passed in as a build-arg (see build-docker.sh) because
# `.dockerignore` excludes `.git`, so the `git_version!()` macro can't read
# `git describe` at compile time. The `version-from-env` feature switches
# the source of GIT_VERSION from the macro to env!("GIT_VERSION").
#
# cargo-auditable embeds an SBOM in the binary so `cargo audit bin` can find
# known vulnerabilities in the deps later without needing the source tree.

FROM rust:alpine AS builder
# Alpine's libpcap-dev bundles both headers AND libpcap.a - no separate
# -static subpackage like Debian. The `pcap` crate picks up libpcap via
# pkg-config; since libpcap.a is next to libpcap.so, the static archive is
# used automatically under +crt-static (which refuses to link shared libs).
RUN apk add --no-cache musl-dev libpcap-dev

WORKDIR /src

COPY Cargo.toml ./
# First install cargo-auditable before adding/compiling the source. Saves us a
# few rebuilds.
RUN cargo install cargo-auditable cargo-audit

COPY src ./src

ARG GIT_VERSION
ENV GIT_VERSION=${GIT_VERSION}

#RUN RUSTFLAGS="-C target-feature=+crt-static -L /usr/lib -l static=pcap"
RUN cargo auditable build \
        --features=version-from-env \
        --release \
        --target x86_64-unknown-linux-musl
RUN strip /src/target/x86_64-unknown-linux-musl/release/dnsqmon

# Sanity check: confirm the binary is really statically linked. We can't
# use `ldd` here -- musl's ldd on a fully-static musl binary prints the
# loader path with an address (e.g. "/lib/ld-musl-x86_64.so.1 (0x...)")
# and exits 0, which *looks* dynamic but isn't. glibc's ldd gets this
# right ("statically linked") but we're inside Alpine.
#
# Instead, check the ELF dynamic section directly. A truly static binary
# has no NEEDED entries (no shared libraries required) and no PT_INTERP
# program header (no dynamic loader).
RUN apk add --no-cache --virtual .verify binutils \
    && ! readelf -d /src/target/x86_64-unknown-linux-musl/release/dnsqmon \
         | grep -q 'NEEDED' \
    && ! readelf -l /src/target/x86_64-unknown-linux-musl/release/dnsqmon \
         | grep -q 'INTERP' \
    && apk del .verify

FROM scratch
COPY --from=builder /src/target/x86_64-unknown-linux-musl/release/dnsqmon /dnsqmon
ENTRYPOINT ["/dnsqmon"]
