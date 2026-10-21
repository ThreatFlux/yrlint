# Stable dependency and security review

Reviewed 2026-10-21 against fetched main `4fc4cf6`, following merged dependency rollup [19](https://github.com/ThreatFlux/yrlint/pull/19). Complete paginated open PR and code-scanning inventories returned zero entries. No alerts were dismissed. All direct/dev crates already match the latest stable non-yanked releases in the official crates.io sparse index, and `cargo update` changes zero locked packages. Rust 1.99.1 is current in the official stable channel manifest.

The current latest GNU runtime still carries glibc/GCC/zlib packages with known unresolved source-package findings. YRLint uses Rust parsing/regex and needs no native analysis ABI, so the runtime deliberately adapts the static-musl build pattern rather than claiming byte identity with the generic GNU template. The build pins official Rust 1.99.1 on Alpine 3.24, preserves all features, explicitly links maintained system musl instead of Rust's older bundled libc, proves static PIE and absence of dynamic dependencies in app/tini, and records actual linker provenance. The final distroless/static image omits those unused shared runtime packages.

A maintained trust-store stage copies actual fixed Debian CA data AND its exact installed supplier package record, requiring at least 20250419+deb13u1. Validation checks the two distrusted roots are absent; no package version is relabeled independently of its data. Both source images are pinned by current registry digests.

`make ci` passed formatting, Clippy, and all tests. `make docker-smoke` exercises the image's actual parser against good and complex bundled rules and verifies static/native/CA provenance. Additional container and current all-severity scan results are recorded in the PR. No Cargo API or consumer minimum-Rust requirement is changed.

Sources: [official Rust stable manifest](https://static.rust-lang.org/dist/channel-rust-stable.toml), [Rust link-self-contained semantics](https://doc.rust-lang.org/rustc/codegen-options/index.html#link-self-contained), [Debian CA advisory](https://www.debian.org/security/2026/dsa-6572).

Native AMD64 and ARM64 CI each build the complete image, execute actual parser fixtures and static provenance checks, and upload a separate all-severity OS/Cargo scan.

Local ARM64 validation passed: the actual good/complex parser smoke tests, static PIE/native musl/CA record checks, and a fresh Trivy 0.76.0 scan with zero OS and Cargo findings across all severities. The CI matrix separately builds and verifies native AMD64 and ARM64. Builder Cargo jobs are capped at two without changing shipped functionality.
