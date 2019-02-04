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

#ifdef TGL_AVOID_OPENSSL

#include <gcrypt.h>

#include "../tgl.h"
#include "../tgl-inner.h"
#include "err.h"

void TGLC_err_print_errors_fp (FILE *fp) {
  // Can't print anything meaningful, so don't.
  (void) fp;
}

int TGLC_init (struct tgl_state *TLS) {
  vlogprintf (E_NOTICE, "Init gcrypt\n");
  // https://gnupg.org/documentation/manuals/gcrypt/Initializing-the-library.html
  // https://lists.gnupg.org/pipermail/gcrypt-devel/2003-August/000458.html

  if (gcry_control (GCRYCTL_INITIALIZATION_FINISHED_P)) {
    // Someone else already *completed* it.
    vlogprintf (E_NOTICE, "Init gcrypt: already initialized -- good\n");
    return 0;
  }

  if (gcry_control (GCRYCTL_ANY_INITIALIZATION_P)) {
    // Someone else already *started* it without *completing*.
    vlogprintf (E_WARNING, "Init gcrypt: already started *but not completed* by third party -- bad\n");
    vlogprintf (E_WARNING, "Init gcrypt: ... not trying to init gcrypt then.\n");
    return 0;
  }

  if (!gcry_check_version (GCRYPT_VERSION)) {
    vlogprintf (E_ERROR, "Init gcrypt: version mismatch!\n");
    return -1;
  }

  gcry_error_t err = gcry_control (GCRYCTL_DISABLE_SECMEM, NULL, 0);
  if (err != GPG_ERR_NO_ERROR) {
    vlogprintf (E_ERROR, "Init gcrypt: secmem failed?!\n");
    return -1;
  }

  /* Tell Libgcrypt that initialization has completed. */
  err = gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
  if (err != GPG_ERR_NO_ERROR) {
    vlogprintf (E_ERROR, "Init gcrypt: init failed?!\n");
    return -1;
  }

  return 0;
}

#endif
