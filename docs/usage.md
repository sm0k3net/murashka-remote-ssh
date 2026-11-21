# Use the workspace

## Add an SSH host

1. Open an owner workspace. Select **Add** beside **Hosts** and enter the address, SSH port, and username.
2. Select **Fetch host fingerprint**. Compare it with the result from a trusted console on the target. For an Ed25519 host key, run:

       ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub

   Use the matching host key algorithm if the server presents another key. Confirm the comparison before saving. The gateway pins the exact key, including for tunnels. If the host key changes legitimately, independently verify the replacement and remove and re-add the saved host.
3. Enter a dedicated SSH private key, or a password if the SSH server permits password authentication. With key authentication, enroll the corresponding public key on the destination first. The gateway never needs your SSH agent.

## Open shells and work with files

Choose a host and select **+ Terminal**. Each tab has its own shell. Select **Split** to see up to four sessions together, and use **Find output** to search the active terminal.

In **Files**, choose a host and directory in each pane. For example, put staging:/home/deploy/configs on the left and build:/home/deploy/incoming on the right. Drag a file or folder to the other pane, or use **Copy**, then confirm the destination. A queued job streams through the gateway and preserves the source. Existing destinations are refused. Use **Transfer history** to check progress or cancel. An interrupted folder job can leave completed files at the destination.

Click a UTF-8 file to edit it. The editor checks whether the content changed after it was opened. Use **Upload** or **Download** for local files. Browser transfers allow up to 10 MiB per file and the editor allows 512 KiB. Cross-host copies are limited to 256 MiB and 5,000 entries per job, with a 2 MiB/s cap and two concurrent transfers. Copies do not follow symbolic links inside the source tree.

## Check resources

Select a host and open **Monitoring**. The gateway runs a short Python collector over SSH, without installing a service on the host. It samples CPU, memory, the root filesystem, and the busiest processes. Refresh requests reuse a fresh sample for up to 25 seconds. Monitoring is on demand and does not send telemetry to an external service.

## Open a tunnel

**Example: reach a staging web app on port 8080.** Select **Tunnels → Add tunnel**, choose **Reach a remote service**, and set the destination to 127.0.0.1:8080. This address is evaluated from the selected SSH host. Choose an unused gateway listen port, or 0 to allocate one. Save and start the tunnel.

- From the gateway, connect to 127.0.0.1 at the listen port shown on the card.
- From your computer, select **Computer bridge**, choose a local port, and extract the ZIP. In that directory, run python3 bridge.py, or py -3 bridge.py on Windows. Use the local address printed by the bridge. Keep the bridge running while you use it.
- For SOCKS5, choose **SOCKS5 proxy** and configure your TCP client with the loopback address shown by the gateway or bridge. Use SOCKS5 with remote DNS resolution when needed. UDP is outside this feature.

For reverse forwarding, enable allow_reverse in the private gateway configuration and restart it. On every participating OpenSSH server, verify GatewayPorts is set to no and that SSH forwarding is permitted for the account. A remote server can override requested listener bindings. Use the feature only with trusted servers whose forwarding policies you control.

Auto-start saves the gateway listener across restarts. **Stop** also disables auto-start. A dropped SSH transport is retried, but connections already in progress need to reconnect. Profile listeners are available to other processes on the machine where they bind, so run them on trusted machines. A downloaded bridge ZIP includes an expiring access credential. Keep it private, and request a new one after the linked workspace expires or is revoked.

## Share one host

On the gateway:

    ./murashka hosts
    ./murashka grant --guest-host 1 --minutes 30

A guest can open a terminal and use SFTP with that saved account. This is operational access. Create a least-privilege SSH account first if the guest needs limited permissions. Revoke access with ./murashka revoke GRANT_ID. Revocation closes the gateway session and its channels. Session revocation does not terminate independently detached server jobs or stop owner-managed tunnel profiles.
