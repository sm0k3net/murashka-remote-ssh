#!/bin/sh
set -eu
cd "$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
python3 -c 'import sys; sys.version_info >= (3, 12) or sys.exit("Python 3.12 or newer is required.")'
python3 -m venv .venv
.venv/bin/python -m pip install --requirement remote/requirements.txt
printf '%s\n' 'Setup complete. Run ./murashka init --local-tls for a local evaluation, or see docs/install.md for a remote deployment.'
