# Telegram, security reviews and remote desktops

## Open a server from Telegram

Use a dedicated bot created through [BotFather](https://t.me/BotFather). Enable the integration on the gateway account:

    ./murashka telegram-setup
    ./murashka telegram

Enter the fresh bot token at the hidden prompt and allow your own numeric Telegram user ID. Start the browser gateway separately. Open the bot in a private chat and send /help.

| Example | Result |
| --- | --- |
| /hosts | List display names and host IDs. |
| /status 1 | Show the last sampled CPU, RAM and disk usage, its age, and the last security review time if available. |
| /connect 1 | Create a 30-minute password-protected browser workspace for host 1. The guest can use the host's saved SSH account for terminals and SFTP. |
| /revoke GRANT_ID | Revoke a link issued by this bot. |

The gateway polls Telegram's Bot API outbound. Group messages and other senders are ignored. The chat contains access links and their passwords, so keep the chat private and revoke links after use. Telegram transports and stores bot messages. Use the local CLI when the access credentials must stay outside Telegram. Browser connections need a reachable HTTPS origin. Localhost only works in a browser running on the gateway itself.

For continuous operation, install the optional service:

    install -Dm644 deploy/murashka-telegram.service ~/.config/systemd/user/murashka-telegram.service
    systemctl --user daemon-reload
    systemctl --user enable --now murashka-telegram

Use one poller per token. The bot configuration is stored inside the gateway's private state directory. Keep it out of source control and backups destined for public storage.

## Review a Linux server

1. Select the host in an owner workspace and open **Security**.
2. Run **Run read-only review**. It runs as the saved SSH user and gathers information from built-in operating system tools.
3. Read the observations and coverage, then use **Download HTML report** for the full inventory.
4. After independently verifying a known-good state, select **Accept fingerprint baseline**. Future reviews compare the readable selected configuration hashes with that baseline.

Example: after changing SSH policy on a staging VM, compare a fresh report with the accepted baseline. Check the effective sshd settings and changes under sshd_config.d. Verify service status and the server's access path before accepting an updated baseline.

Reports can show local APT update candidates using the existing indexes, listeners, services, account metadata and selected hashes. Results depend on the saved SSH user's access, the package manager and installed utilities. Key material, passwords, shadow data and full configuration bodies are outside the collector. Checks do not refresh APT indexes, attempt exploitation, apply fixes or send inventories to an advisory service. An empty finding list does not establish that the host is secure. Keep downloaded reports private.

## Open or provision a Linux desktop

For an existing VNC display, select the host, open **Desktop**, choose **:0** or **:1**, and click **Open browser desktop**. Enter the VNC password if asked. The gateway connects to loopback on that host via SSH. The SSH account and server policy must allow TCP forwarding to the VNC port.

For automatic setup:

1. Choose a Debian or Ubuntu host with systemd, APT, Python 3, and a root SSH account or working passwordless sudo. Use an SSH account you control. The installer uses a separate unprivileged account for the desktop session.
2. Choose **Openbox** for a lighter session or **Xfce** for a full desktop. Openbox requires at least 768 MiB RAM, 384 MiB available RAM and 1 GiB disk free. Xfce requires at least 2 GiB RAM, 1 GiB available RAM and 3 GiB disk free.
3. Select **Install desktop**, review the confirmation, and wait for completion. The operation refreshes APT indexes, installs packages from the host's configured repositories and enables a systemd service. It refuses existing managed configurations or a busy port 5901.
4. Open **VNC display :1**. The generated VNC password is stored encrypted in the gateway. The listener stays on loopback and the browser uses the existing HTTPS and SSH connection.

Example: open an Xfce session on a Debian VM to inspect an application that only provides a graphical interface. Disconnecting the browser leaves the desktop running. Use **Restart managed desktop** to restart it, or **Remove managed desktop** to remove the service and its credentials. Removal preserves the dedicated user's home and installed packages. If a connection drops during installation, check the host service state before retrying.

## Scope of the public edition

The public edition also supports split SSH terminals, output search, SFTP copy jobs, on-demand resource monitoring, workspace revocation and three SSH tunnel modes. See [workspace examples](usage.md).

The private deployment has additional integration points. Outbound SSH connectors, fleet alerting and audit schedules, advisory enrichment and automated remediation, S3/backup providers, native RDP bridges, and AI/MCP automation are outside this version. The public Telegram bot handles this SSH workspace. It does not carry the private VPN, Vaultwarden, or custom cloud configuration.
