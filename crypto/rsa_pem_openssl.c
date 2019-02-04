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

#include "config.h"

#ifndef TGL_AVOID_OPENSSL

//#include <stddef.h> /* NULL */

#include <openssl/rsa.h>
#include <openssl/pem.h>

#include "bn.h"
#include "meta.h"
#include "rsa_pem.h"

#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || (defined(LIBRESSL_VERSION_NUMBER) && (LIBRESSL_VERSION_NUMBER < 0x2070000fL))

int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d)
{
   /* If the fields n and e in r are NULL, the corresponding input
    * parameters MUST be non-NULL for n and e.  d may be
    * left NULL (in case only the public key is used).
    */
   if ((r->n == NULL && n == NULL)
       || (r->e == NULL && e == NULL))
       return 0;

   if (n != NULL) {
       BN_free(r->n);
       r->n = n;
   }
   if (e != NULL) {
       BN_free(r->e);
       r->e = e;
   }
   if (d != NULL) {
       BN_free(r->d);
       r->d = d;
   }

   return 1;
}

void RSA_get0_key(const RSA *r,
		  const BIGNUM **n, const BIGNUM **e, const BIGNUM **d)
{
  if (n != NULL)
    *n = r->n;
  if (e != NULL)
    *e = r->e;
  if (d != NULL)
    *d = r->d;
}

#endif

TGLC_WRAPPER_ASSOC(rsa,RSA)

// TODO: Refactor crucial struct-identity into its own header.
TGLC_WRAPPER_ASSOC(bn,BIGNUM)

TGLC_rsa *TGLC_rsa_new (unsigned long e, int n_bytes, const unsigned char *n) {
  RSA *ret = RSA_new ();
  TGLC_bn* e_tglcbn = TGLC_bn_new ();
  TGLC_bn_set_word (e_tglcbn, e);
  RSA_set0_key(ret, unwrap_bn (TGLC_bn_bin2bn (n, n_bytes, NULL)), unwrap_bn(e_tglcbn), NULL); 
  return wrap_rsa (ret);
}

TGLC_bn *TGLC_rsa_n (TGLC_rsa * key) {
  const BIGNUM *n;
  RSA_get0_key( unwrap_rsa(key),  &n, NULL, NULL);
  return wrap_bn(n);		
}

TGLC_bn *TGLC_rsa_e (TGLC_rsa * key) {
  const BIGNUM *e;
  RSA_get0_key( unwrap_rsa(key),  NULL, &e, NULL);
  return wrap_bn(e);		
}

void TGLC_rsa_free (TGLC_rsa *p) {
  RSA_free (unwrap_rsa (p));
}

TGLC_rsa *TGLC_pem_read_RSAPublicKey (FILE *fp) {
  return wrap_rsa (PEM_read_RSAPublicKey (fp, NULL, NULL, NULL));
}

#endif
