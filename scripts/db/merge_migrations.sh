#!/bin/sh
# Generate a validated SQLite migration baseline without touching current files.
set -eu
script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
exec python3 "$script_dir/baseline.py" merge "$@"
