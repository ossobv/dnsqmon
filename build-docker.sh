#!/bin/sh
set -e
set -x
here=$(cd "$(dirname "$0")"; pwd)
gitversion=$(git describe --always --dirty=+modified)
version=$(echo "$gitversion" | sed -e 's/[^A-Za-z0-9.-]\+/_/g')
sudo docker build --build-arg="GIT_VERSION=$gitversion" --progress=plain -t "build-dnsqmon:$version" "$here"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
sudo docker image save "build-dnsqmon:$version" | tar -C "$tmp" -x

if test -f "$tmp/repositories"; then
    layertar=$(jq -r ".[\"build-dnsqmon\"][\"$version\"]" <"$tmp/repositories")
    if test -n "$layertar"; then
        layertar=$tmp/blobs/sha256/$layertar
    fi
else
    layertar=$(find "$tmp" -type f -name layer.tar)
fi
if test -z "$layertar"; then
    echo "$0: could not parse docker layout to extract output" >&2
fi
tar -xvf "$layertar"
ls -l ./dnsqmon
