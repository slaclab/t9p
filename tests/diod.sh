#!/usr/bin/env bash
set -e

cd "$(dirname "${BASH_SOURCE[0]}")"

if ! which diod > /dev/null; then
    echo "Unable to find diod. Make sure it's installed and that you are running as root"
fi

diod -f -L stderr -e $PWD/fs -l 0.0.0.0:10002 -n
