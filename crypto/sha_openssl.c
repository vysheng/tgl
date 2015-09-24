/* 
    This file is part of tgl-library

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

    Copyright Ben Wiederhake 2015
*/

#include "crypto-config.h"

#ifndef TGL_AVOID_OPENSSL_SHA

#include <openssl/sha.h>

#include "sha.h"

unsigned char* TGLC_sha1 (const unsigned char *d, size_t n, unsigned char *md) {
  return SHA1 (d, n, md);
}
unsigned char* TGLC_sha256 (const unsigned char *d, size_t n, unsigned char *md) {
  return SHA256 (d, n, md);
}

#endif
