# Telegram library

This is library that handles Telegram API and protocol.

> This is a fork of [vysheng's repository](https://github.com/vysheng/tgl).

If you're looking for client CLI implementation, check [TG repository](https://github.com/vysheng/tg) instead. 

Build status:

| Repository                                             | Status|
| ------------------------------------------------------ | ----- |
| [vysheng](https://github.com/vysheng/tgl) (main)       | [![Build Status](https://travis-ci.org/vysheng/tgl.svg)](https://travis-ci.org/vysheng/tgl) |
| [kenorb-contrib](https://github.com/kenorb-contrib/tgl) | [![Build Status](https://travis-ci.org/kenorb-contrib/tgl.svg)](https://travis-ci.org/kenorb-contrib/tgl) |

Current versions:

- `scheme.tl`: Layer 38
- `encrypted_scheme.tl`: Layer 23

### API, Protocol documentation

Documentation for Telegram API is available here: https://core.telegram.org/api

Documentation for MTproto protocol is available here: https://core.telegram.org/mtproto

### Installation

Clone this GitHub repository with `--recursive` parameter to clone submodules.

     git clone --recursive https://github.com/CHANGETHIS/tgl.git && cd tgl

#### Linux and BSDs

Install libs: openssl, zlib
if you want to use provided net/timers then install libevent and add --enable-libevent key to configure

You can also avoid the OpenSSL dependency: Install gcrypt (>= 1.60, Debian derivates know it as "libgcrypt20-dev"), and add --disable-openssl key to configure

Then,

     ./configure
     make

#### Android
Install libs: openssl, openssl(android), zlib
if you want to use provided net/timers then install libevent and add --enable-libevent key to configure

Then,

     export ANDROID_NDK=<Path_to_Android_NDK>
     export OPENSSL_ROOT=<Path_to_Android_version_of_OpenSSL_root_dir>
     ./configure
     make -f Makefile.android


### Contacts 
If you would like to ask a question, you can write to my telegram or to the github (or both). To contact me via telegram, you should use import_card method with argument 000653bf:0738ca5d:5521fbac:29246815:a27d0cda

