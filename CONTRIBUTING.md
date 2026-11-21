# Contributing

Open an issue for a reproducible bug or a scoped feature request. Please use synthetic hostnames and paths in examples and keep vulnerability reports private as described in [SECURITY.md](SECURITY.md).

Run locally from the repository root:

    ./setup.sh
    PYTHONPATH=remote .venv/bin/python -m unittest discover -s tests -v
    node --check remote/static/workspace.js

The tests create disposable SSH endpoints on loopback with temporary credentials. No cloud account is needed. Document new configuration alongside the implementation, preserve SSH host-key pinning, and include a way to verify changes on a fresh installation.

By submitting a contribution, you represent that you have the right to submit it and release it under the project's Apache-2.0 license.
