# Third-party notices

The Apache-2.0 license covers the project code. Bundled browser assets retain their original MIT notices:

| Asset | Version | Source | Notice |
| --- | --- | --- | --- |
| xterm.js | 6.0.0 | [xterm.js](https://github.com/xtermjs/xterm.js) | [License](remote/static/vendor/xterm.LICENSE) |
| xterm.js fit add-on | 0.11.0 | [xterm.js fit](https://www.npmjs.com/package/@xterm/addon-fit) | [License](remote/static/vendor/addon-fit.LICENSE) |
| xterm.js search add-on | 0.16.0 | [xterm.js search](https://www.npmjs.com/package/@xterm/addon-search) | [License](remote/static/vendor/addon-search.LICENSE) |

The installed Python runtime dependencies include [aiohttp](https://github.com/aio-libs/aiohttp), [AsyncSSH](https://github.com/ronf/asyncssh), and [cryptography](https://github.com/pyca/cryptography). Python package licenses are distributed in their package metadata. The repository does not bundle these packages in source downloads.

The browser desktop includes noVNC 1.7.0 and its bundled pako sources. The [upstream noVNC project](https://github.com/novnc/noVNC) uses the Mozilla Public License 2.0 and includes components with BSD notices. The source bundle at remote/novnc-1.7.0.tar.gz preserves AUTHORS, the applicable license files and the pako notice.
