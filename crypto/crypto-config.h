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

#ifndef __TGL_CRYPTO_CRYPTO_CONFIG_H__
#define __TGL_CRYPTO_CRYPTO_CONFIG_H__

#define TGL_AVOID_OPENSSL_AES
#define TGL_AVOID_OPENSSL_MD5

#ifdef TGL_AVOID_OPENSSL
#define TGL_AVOID_OPENSSL_BN
#define TGL_AVOID_OPENSSL_ERR
#define TGL_AVOID_OPENSSL_RAND
#define TGL_AVOID_OPENSSL_SHA
#endif

#endif
