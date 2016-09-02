#!/bin/sh
#
# install pyOpenSSL with homebrew (OSX)

LIBFFI_VERSION=3.0.13

export LDFLAGS="-L$(brew --prefix openssl)/lib -L$(brew --prefix libffi)/lib"
export CFLAGS="-I$(brew --prefix openssl)/include -I/usr/local/homebrew/Cellar/libffi/${LIBFFI_VERSION}/lib/libffi-${LIBFFI_VERSION}/include"

pip install pyOpenSSL
