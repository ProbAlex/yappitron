# Security policy

Yappitron is an end-to-end encrypted messenger. It is early-stage software and has **not** been independently audited. Do not rely on it for high-risk communication yet.

## Reporting a vulnerability

Please report security issues **privately**, not in public issues or pull requests.

Use GitHub's private vulnerability reporting: the repository's **Security** tab → **Report a vulnerability**.

Include what you found, how to reproduce it, and the impact you expect. You will get an acknowledgement, and we will work with you on a fix and on coordinated disclosure.

## Scope

In scope: the Rust crates in `crates/`, the Flutter app in `app/`, and the deployment configuration in `deploy/`.

Out of scope: social engineering, denial of service by raw traffic volume, and vulnerabilities in third-party services we depend on (report those upstream).

## What the server can and cannot see

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
