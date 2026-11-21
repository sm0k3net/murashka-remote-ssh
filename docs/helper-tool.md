# Integrate Murashka Helper Tool

[Murashka Helper Tool](https://github.com/sm0k3net/murashka-helper-tool) is the standalone optional Telegram companion. It lists allowlisted hosts, reads cached status, and sends an approval link. After independent browser approval, it can request or revoke a 30-minute guest workspace through the local broker. Workspace credentials are returned in the browser.

[Project website](https://sm0k3net.github.io/murashka-remote-ssh/helper-tool/)

The separate broker is available from Remote SSH v0.2.1. Using a dedicated bot for Helper avoids competing Telegram pollers. The built-in Telegram integration remains available for existing installations.

## Set up the broker

As the account that runs Remote SSH, with the existing state directory:

    ./murashka hosts
    ./murashka helper-init
    ./murashka helper-broker --allow-host 1

Replace 1 with an existing host ID. Repeat --allow-host to allow multiple hosts. The gateway itself must also be running. Pass --state before the command if using a custom Remote SSH state directory.

The default socket is helper.sock inside Remote SSH state. Its mode is 0660, and the containing state directory is private. Keep helper-token mode 0600. The token grants access only to the broker's limited operations and listed hosts, so treat it as an access credential.

See [Helper installation](https://github.com/sm0k3net/murashka-helper-tool/blob/main/docs/install.md) for same-account and separate-account setup. A separate account gets the broker token and group socket access, without access to the Remote SSH database or encryption key. Use --socket to bind inside a dedicated, controlled directory with the correct group. Do not put the socket in a publicly writable directory.

For a persistent systemd user service, copy the example and edit ExecStart to match the actual checkout and host IDs before enabling it:

    install -Dm644 deploy/murashka-helper-broker.service.example ~/.config/systemd/user/murashka-helper-broker.service
    systemctl --user edit --full murashka-helper-broker
    systemctl --user daemon-reload
    systemctl --user enable --now murashka-helper-broker

The broker issues guest links only, at most ten active. The saved SSH account determines guest permissions. Owner grants and links created through other entry points are outside the broker's revocation scope. Report activity and session expiry remain enforced by the Remote SSH service.
