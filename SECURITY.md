# Security policy

Report a vulnerability privately through GitHub's **Security → Report a vulnerability** when available, or privately contact the maintainer listed on the repository's GitHub profile to arrange a secure channel. Please include the release version, a concise description, and sanitized reproduction steps. Keep credentials, access links, connection archives, and database files out of public issues.

Security fixes are tracked for the latest published release. This project is an early release for a single trusted operator. Operators can reach services from the gateway and act with the full permissions of the SSH accounts they register. Use a dedicated unprivileged gateway account, verified SSH server fingerprints, a trusted HTTPS proxy, and least-privilege accounts on managed hosts. Restrict network access where practical.

The gateway verifies the configured web origin and CSRF token for authenticated changes. SSH credentials are encrypted at rest with an installation-generated key. Anyone who controls the gateway account and reads both the state and its key can decrypt those credentials. Do not publish state, workspace URLs or passwords, TLS private keys, bridge bundles, or screenshots that contain real account details.
