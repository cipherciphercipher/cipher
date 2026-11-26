#!/bin/sh
# Cipher installer for macOS and Linux: ./install.sh, or ./install.sh --help for options.
command -v node >/dev/null 2>&1 || { echo "Node.js is needed: https://nodejs.org"; exit 1; }
exec node "$(dirname "$0")/scripts/install.mjs" "$@"
