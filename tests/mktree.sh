#!/usr/bin/env bash

cd "$(dirname "${BASH_SOURCE[0]}")"

FILES="a.txt b.txt c jkjgdjsdkgsdjg.c aaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

mkdir -p fs
cd fs

DIRS=". something other"
for d in $DIRS; do
    mkdir -p $d
    for f in $FILES; do
        base64 /dev/urandom | head -c 8192 > "$d/$f";
    done
done