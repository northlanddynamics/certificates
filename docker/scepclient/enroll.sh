#!/bin/sh
# Enrolls with scepclient, passing it every argument, and prints the certificate it was issued on stdout.
set -e
dir=$(mktemp -d)
scepclient -private-key "$dir/key.pem" -certificate "$dir/cert.pem" "$@" >&2
cat "$dir/cert.pem"
