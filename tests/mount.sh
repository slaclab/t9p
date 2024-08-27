#!/usr/bin/env bash
set -e
cd "$(dirname "${BASH_SOURCE[0]}")"

mkdir -p mnt
#mount -t 9p -i -o trans=tcp,port=10002,aname=$PWD/fs -v -n localhost ./mnt
9mount -u -a $PWD/fs tcp!127.0.0.1!10002 ./mnt