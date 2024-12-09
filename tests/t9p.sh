#!/usr/bin/env bash

cd "$(dirname "${BASH_SOURCE[0]}")"

$DEBUGGER ../t9p -a $PWD/fs/ -m $PWD/mnt 127.0.0.1:10002
