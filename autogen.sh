#!/bin/sh -e

autoreconf --install

args="--prefix=/usr \
      --sysconfdir=/etc"

echo
echo "----------------------------------------------------------------"
echo "Initialized build system. For a common configuration please run:"
echo "----------------------------------------------------------------"
echo
echo "./configure CFLAGS='-g' $args"
echo
