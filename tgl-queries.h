#ifndef __TGL_QUERIES_H__
#define __TGL_QUERIES_H__

#include "tgl.h"

void tgl_do_get_channels_dialog_list (struct tgl_state *TLS, int limit, int offset, void (*callback)(struct tgl_state *TLS, void *callback_extra, int success, int size, tgl_peer_id_t peers[], int last_msg_id[], int unread_count[]), void *callback_extra);
#endif
