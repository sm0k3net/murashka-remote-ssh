# Install and configure

The gateway needs Python 3.12+ and an operating system with Python virtual environments. The instructions below target Ubuntu 24.04 LTS. SSH and SFTP use the chosen account on each destination. Agentless monitoring requires Python 3 and /proc on the destination Linux host.

## 1. Install as an unprivileged account

Use the account that will operate the gateway. Keep this checkout and its state under that account.

    sudo apt update
    sudo apt install git python3 python3-venv openssl
    git clone https://github.com/sm0k3net/murashka-remote-ssh.git ~/murashka-remote-ssh
    cd ~/murashka-remote-ssh
    ./setup.sh

The setup script creates a virtual environment, installs Python dependencies and unpacks the bundled browser VNC client. It does not create system accounts, modify SSH configuration, or install a reverse proxy.

## 2. Choose HTTPS

### Local evaluation

Run the gateway and browser on the same machine:

    ./murashka init --local-tls
    ./murashka serve

The command generates a self-signed certificate for localhost. Check its SHA-256 fingerprint on the same machine if your browser prompts you to trust it:

    openssl x509 -in ~/.local/state/murashka-remote-ssh/localhost.crt -noout -fingerprint -sha256

Accept the certificate only for your own localhost evaluation. The computer bridge uses system certificate validation. If you use the bridge in this mode, it also needs to trust this exact local certificate, for example through the SSL_CERT_FILE environment variable.

### Remote server

Point your chosen DNS name at your gateway and provision trusted HTTPS at a reverse proxy. Replace the example hostname:

    ./murashka init --origin https://remote.example.org
    ./murashka serve

The Python gateway listens at 127.0.0.1:8765. Configure the proxy on the same machine and allow WebSocket upgrades. The proxy's HTTPS hostname must match the configured origin exactly. This repository includes a [Caddy example](../deploy/Caddyfile.example). A firewall or VPN can limit who reaches your proxy. Keep the Python listener on loopback.

Check the service without credentials:

    curl --fail https://remote.example.org/healthz

The health endpoint returns a simple status. It does not verify any SSH connection.

## 3. Open your first workspace

In another terminal as the same user, run:

    cd ~/murashka-remote-ssh
    ./murashka grant --minutes 30

Open the full URL and enter the printed password. Treat both as credentials. To revoke a link, use its grant ID:

    ./murashka grants
    ./murashka revoke GRANT_ID

Optional: for an account installed at ~/murashka-remote-ssh on a systemd host:

    install -Dm644 deploy/murashka-remote-ssh.service ~/.config/systemd/user/murashka-remote-ssh.service
    systemctl --user daemon-reload
    systemctl --user enable --now murashka-remote-ssh

Stop any foreground instance before starting the unit. On hosts that stop user services at logout, an administrator can enable lingering for the installation account if the gateway should start at boot and persist after logout. Check its logs with journalctl --user -u murashka-remote-ssh.

## State, backup and upgrades

Default state is ~/.local/state/murashka-remote-ssh. Use the global --state argument before the command, or set MURASHKA_STATE consistently for both setup and service administration. Keep the directory mode at 0700 and its contents private. Local configuration is in config.json. Keep allow_reverse false unless you have reviewed the target SSH server's GatewayPorts and forwarding policies.

The SQLite database contains encrypted SSH credentials and operational metadata. The fernet-key file can decrypt saved credentials and must be protected as carefully as the database itself. Stop the service and copy the complete directory to an encrypted backup. Restore it only under the intended gateway account, with private file permissions. When migrating, review the origin and revoke existing grants if their access links should stop working.

For upgrades, stop the gateway, take the backup above, check the [changelog](../CHANGELOG.md), switch your clean checkout to the desired release tag, and rerun ./setup.sh. Restart the service and retest an SSH connection. A software rollback may also require restoring the pre-upgrade state. Keep source code and state on separate paths.

## Optional host operations

After updating to 0.2 or later, rerun ./setup.sh before starting the gateway. For Telegram setup, read-only host reviews and graphical access, see [host operations](host-operations.md).
