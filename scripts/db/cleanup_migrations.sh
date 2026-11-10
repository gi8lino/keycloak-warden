#!/bin/sh
# Replace old migrations with the separately validated SQLite baseline.
set -eu
script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
exec python3 "$script_dir/baseline.py" cleanup "$@"
