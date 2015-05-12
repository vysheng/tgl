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

    Copyright Vitaly Valtman 2013-2015
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define _FILE_OFFSET_BITS 64
#include <string.h>
#include <memory.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/utsname.h>


#include "mtproto-client.h"
#include "queries.h"
#include "tree.h"
#include "mtproto-common.h"
//#include "telegram.h"
#include "tgl-structures.h"
//#include "interface.h"
//#include "net.h"
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/md5.h>

#include "no-preview.h"
#include "tgl-binlog.h"
#include "updates.h"
#include "auto.h"
#include "tgl.h"
#include "tg-mime-types.h"
#include "mtproto-utils.h"

#define sha1 SHA1

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

//int want_dc_num;
//char *get_downloads_directory (void);
//extern int offline_mode;

//long long cur_uploading_bytes;
//long long cur_uploaded_bytes;
//long long cur_downloading_bytes;
//long long cur_downloaded_bytes;

//extern int binlog_enabled;
//extern int sync_from_start;

//static int queries_num;

static void out_peer_id (struct tgl_state *TLS, tgl_peer_id_t id);
#define QUERY_TIMEOUT 6.0

#define memcmp8(a,b) memcmp ((a), (b), 8)
DEFINE_TREE (query, struct query *, memcmp8, 0) ;

struct query *tglq_query_get (struct tgl_state *TLS, long long id) {
  return tree_lookup_query (TLS->queries_tree, (void *)&id);
}

static int alarm_query (struct tgl_state *TLS, struct query *q) {
  assert (q);
  vlogprintf (E_DEBUG - 2, "Alarm query %lld\n", q->msg_id);
  
  TLS->timer_methods->insert (q->ev, QUERY_TIMEOUT); 

  if (q->session->session_id == q->session_id && q->session_id) {
    clear_packet ();
    out_int (CODE_msg_container);
    out_int (1);
    out_long (q->msg_id);
    out_int (q->seq_no);
    out_int (4 * q->data_len);
    out_ints (q->data, q->data_len);
  
    tglmp_encrypt_send_message (TLS, q->session->c, packet_buffer, packet_ptr - packet_buffer, q->flags & QUERY_FORCE_SEND);
  } else {
    q->flags &= ~QUERY_ACK_RECEIVED;
    if (tree_lookup_query (TLS->queries_tree, q)) {
      TLS->queries_tree = tree_delete_query (TLS->queries_tree, q);
    }
    q->session = q->DC->sessions[0];
    q->msg_id = tglmp_encrypt_send_message (TLS, q->session->c, q->data, q->data_len, (q->flags & QUERY_FORCE_SEND) | 1);
    TLS->queries_tree = tree_insert_query (TLS->queries_tree, q, lrand48 ());
    q->session_id = q->session->session_id;
    if (!(q->session->dc->flags & 4) && !(q->flags & QUERY_FORCE_SEND)) {
      q->session_id = 0;
    }
  }
  return 0;
}

void tglq_regen_query (struct tgl_state *TLS, long long id) {
  struct query *q = tglq_query_get (TLS, id);
  if (!q) { return; }
  q->flags &= ~QUERY_ACK_RECEIVED;
  
  if (!(q->session->dc->flags & 4) && !(q->flags & QUERY_FORCE_SEND)) {
    q->session_id = 0;
  }
  vlogprintf (E_NOTICE, "regen query %lld\n", id);
  TLS->timer_methods->insert (q->ev, 0.001);
}

void tglq_query_restart (struct tgl_state *TLS, long long id) {
  struct query *q = tglq_query_get (TLS, id);
  if (q) {
    vlogprintf (E_NOTICE, "restarting query %lld\n", id);
    TLS->timer_methods->remove (q->ev);
    alarm_query (TLS, q);
  }
}

static void alarm_query_gateway (struct tgl_state *TLS, void *arg) {
  alarm_query (TLS, arg);
}


struct query *tglq_send_query_ex (struct tgl_state *TLS, struct tgl_dc *DC, int ints, void *data, struct query_methods *methods, void *extra, void *callback, void *callback_extra, int flags) {
  assert (DC);
  assert (DC->auth_key_id);
  if (!DC->sessions[0]) {
    tglmp_dc_create_session (TLS, DC);
  }
  vlogprintf (E_DEBUG, "Sending query of size %d to DC (%s:%d)\n", 4 * ints, DC->ip, DC->port);
  struct query *q = talloc0 (sizeof (*q));
  q->data_len = ints;
  q->data = talloc (4 * ints);
  memcpy (q->data, data, 4 * ints);
  q->msg_id = tglmp_encrypt_send_message (TLS, DC->sessions[0]->c, data, ints, 1 | (flags & QUERY_FORCE_SEND));
  q->session = DC->sessions[0];
  q->seq_no = q->session->seq_no - 1; 
  q->session_id = q->session->session_id;
  if (!(DC->flags & 4) && !(flags & QUERY_FORCE_SEND)) {
    q->session_id = 0;
  }
  vlogprintf (E_DEBUG, "Msg_id is %lld %p\n", q->msg_id, q);
  q->methods = methods;
  q->type = methods->type;
  q->DC = DC;
  q->flags = flags & QUERY_FORCE_SEND;
  if (TLS->queries_tree) {
    vlogprintf (E_DEBUG + 2, "%lld %lld\n", q->msg_id, TLS->queries_tree->x->msg_id);
  }
  TLS->queries_tree = tree_insert_query (TLS->queries_tree, q, lrand48 ());

  q->ev = TLS->timer_methods->alloc (TLS, alarm_query_gateway, q);
  TLS->timer_methods->insert (q->ev, QUERY_TIMEOUT);

  q->extra = extra;
  q->callback = callback;
  q->callback_extra = callback_extra;
  TLS->active_queries ++;
  return q;
}

struct query *tglq_send_query (struct tgl_state *TLS, struct tgl_dc *DC, int ints, void *data, struct query_methods *methods, void *extra, void *callback, void *callback_extra) {
  return tglq_send_query_ex (TLS, DC, ints, data, methods, extra, callback, callback_extra, 0);
}

static int fail_on_error (struct tgl_state *TLS, struct query *q, int error_code, int l, const char *error) {
  fprintf (stderr, "error #%d: %.*s\n", error_code, l, error);
  assert (0);
  return 0;
}

void tglq_query_ack (struct tgl_state *TLS, long long id) {
  struct query *q = tglq_query_get (TLS, id);
  if (q && !(q->flags & QUERY_ACK_RECEIVED)) { 
    assert (q->msg_id == id);
    q->flags |= QUERY_ACK_RECEIVED; 
    TLS->timer_methods->remove (q->ev);
  }
}

void tglq_query_delete (struct tgl_state *TLS, long long id) {
  struct query *q = tglq_query_get (TLS, id);
  if (!q) {
    return;
  }
  if (!(q->flags & QUERY_ACK_RECEIVED)) {
    TLS->timer_methods->remove (q->ev);
  }
  TLS->queries_tree = tree_delete_query (TLS->queries_tree, q);
  tfree (q->data, q->data_len * 4);
  TLS->timer_methods->free (q->ev);
  TLS->active_queries --;
}

int tglq_query_error (struct tgl_state *TLS, long long id) {
  assert (fetch_int () == CODE_rpc_error);
  int error_code = fetch_int ();
  int error_len = prefetch_strlen ();
  char *error = fetch_str (error_len);
  struct query *q = tglq_query_get (TLS, id);
  if (!q) {
    vlogprintf (E_WARNING, "error for query #%lld: #%d :%.*s\n", id, error_code, error_len, error);
    vlogprintf (E_WARNING, "No such query\n");
  } else {
    if (!(q->flags & QUERY_ACK_RECEIVED)) {
      TLS->timer_methods->remove (q->ev);
    }
    TLS->queries_tree = tree_delete_query (TLS->queries_tree, q);
    int res = 0;

    int error_handled = 0;

    switch (error_code) {
    case 303:
      // migrate
      {
        int offset = -1;
        if (error_len >= 15 && !memcmp (error, "PHONE_MIGRATE_", 14)) {
          offset = 14;
        }
        if (error_len >= 17 && !memcmp (error, "NETWORK_MIGRATE_", 16)) {
          offset = 16;
        }
        if (error_len >= 14 && !memcmp (error, "USER_MIGRATE_", 13)) {
          offset = 13;
        }
        if (offset >= 0) {
          int i = 0; 
          while (offset < error_len && error[offset] >= '0' && error[offset] <= '9') {
            i = i * 10 + error[offset] - '0';
            offset ++;
          }
          if (i > 0 && i < TGL_MAX_DC_NUM) {
            bl_do_set_working_dc (TLS, i);
            q->flags &= ~QUERY_ACK_RECEIVED;
            //q->session_id = 0;
            //struct tgl_dc *DC = q->DC;
            //if (!(DC->flags & 4) && !(q->flags & QUERY_FORCE_SEND)) {
            q->session_id = 0;
            //}
            q->DC = TLS->DC_working;
            TLS->timer_methods->insert (q->ev, 0);
            error_handled = 1;
            res = 1;
          } 
        }
      }
      break;
    case 400:
      // nothing to handle
      // bad user input probably
      break;
    case 401:
      if (!(TLS->locks & TGL_LOCK_PASSWORD)) {
        TLS->locks |= TGL_LOCK_PASSWORD;
        tgl_do_check_password (TLS, NULL, NULL);
      }
      q->flags &= ~QUERY_ACK_RECEIVED;
      TLS->timer_methods->insert (q->ev, 1);
      struct tgl_dc *DC = q->DC;
      if (!(DC->flags & 4) && !(q->flags & QUERY_FORCE_SEND)) {
        q->session_id = 0;
      }         
      error_handled = 1;
      break;
    case 403:
      // privacy violation
      break;
    case 404:
      // not found
      break;
    case 420: 
      // flood
    case 500:
      // internal error
    default:
      // anything else. Treated as internal error
      {
        int wait;
        if (strncmp (error, "FLOOD_WAIT_", 11)) {
          if (error_code == 420) {
            vlogprintf (E_ERROR, "error = '%s'\n", error);
          }
          wait = 10;
        } else {
          wait = atoll (error + 11);
        }
        q->flags &= ~QUERY_ACK_RECEIVED;
        TLS->timer_methods->insert (q->ev, wait);
        struct tgl_dc *DC = q->DC;
        if (!(DC->flags & 4) && !(q->flags & QUERY_FORCE_SEND)) {
          q->session_id = 0;
        }         
        error_handled = 1;
      }
      break;
    }

    if (error_handled) {
      vlogprintf (E_DEBUG - 2, "error for query #%lld: #%d %.*s (HANDLED)\n", id, error_code, error_len, error);
    } else {
      vlogprintf (E_WARNING, "error for query #%lld: #%d %.*s\n", id, error_code, error_len, error);
      if (q->methods && q->methods->on_error) {
        res = q->methods->on_error (TLS, q, error_code, error_len, error);
      }
    }

    if (res <= 0) {
      tfree (q->data, q->data_len * 4);
      TLS->timer_methods->free (q->ev);
    }

    if (res == -11) {
      TLS->active_queries --;
      return -1;
      
    }
  }
  TLS->active_queries --;
  return 0;
}

#define MAX_PACKED_SIZE (1 << 24)
static int packed_buffer[MAX_PACKED_SIZE / 4];

int tglq_query_result (struct tgl_state *TLS, long long id) {
  vlogprintf (E_DEBUG, "result for query #%lld. Size %ld bytes\n", id, (long)4 * (in_end - in_ptr));
  int op = prefetch_int ();
  int *end = 0;
  int *eend = 0;
  if (op == CODE_gzip_packed) {
    fetch_int ();
    int l = prefetch_strlen ();
    char *s = fetch_str (l);
    int total_out = tgl_inflate (s, l, packed_buffer, MAX_PACKED_SIZE);
    vlogprintf (E_DEBUG, "inflated %d bytes\n", total_out);
    end = in_ptr;
    eend = in_end;
    in_ptr = packed_buffer;
    in_end = in_ptr + total_out / 4;
  }
  struct query *q = tglq_query_get (TLS, id);
  if (!q) {
    vlogprintf (E_WARNING, "No such query\n");
    in_ptr = in_end;
  } else {
    if (!(q->flags & QUERY_ACK_RECEIVED)) {
      TLS->timer_methods->remove (q->ev);
    }
    TLS->queries_tree = tree_delete_query (TLS->queries_tree, q);
    if (q->methods && q->methods->on_answer) {
      if (q->type) {
        int *save = in_ptr;
        vlogprintf (E_DEBUG, "in_ptr = %p, end_ptr = %p\n", in_ptr, in_end);
        if (skip_type_any (q->type) < 0) {
          vlogprintf (E_ERROR, "Skipped %ld int out of %ld (type %s)\n", (long)(in_ptr - save), (long)(in_end - save), q->type->type->id);
          assert (0);
        }
        
        assert (in_ptr == in_end);
        in_ptr = save;
      }
      q->methods->on_answer (TLS, q);
      assert (in_ptr == in_end);
    }
    tfree (q->data, 4 * q->data_len);
    TLS->timer_methods->free (q->ev);
    tfree (q, sizeof (*q));

  }
  if (end) {
    in_ptr = end;
    in_end = eend;
  }
  TLS->active_queries --;
  return 0;
} 

static void out_random (int n) {
  assert (n <= 32);
  static char buf[32];
  tglt_secure_random (buf, n);
  out_cstring (buf, n);
}

int allow_send_linux_version;
void tgl_do_insert_header (struct tgl_state *TLS) {
  out_int (CODE_invoke_with_layer);
  out_int (TGL_SCHEME_LAYER);
  out_int (CODE_init_connection);
  out_int (TLS->app_id);
  if (allow_send_linux_version) {
    struct utsname st;
    uname (&st);
    out_string (st.machine);
    static char buf[4096];
    tsnprintf (buf, sizeof (buf) - 1, "%.999s %.999s %.999s\n", st.sysname, st.release, st.version);
    out_string (buf);
    tsnprintf (buf, sizeof (buf) - 1, "%s (TGL %s)\n", TLS->app_version, TGL_VERSION);
    out_string (buf);
    out_string ("En");
  } else { 
    out_string ("x86");
    out_string ("Linux");
    static char buf[4096];
    tsnprintf (buf, sizeof (buf) - 1, "%s (TGL %s)\n", TLS->app_version, TGL_VERSION);
    out_string (buf);
    out_string ("en");
  }
}

/* {{{ Get config */

static void fetch_dc_option (struct tgl_state *TLS) {
  assert (fetch_int () == CODE_dc_option);
  int id = fetch_int ();
  int l1 = prefetch_strlen ();
  char *name = fetch_str (l1);
  int l2 = prefetch_strlen ();
  char *ip = fetch_str (l2);
  int port = fetch_int ();

  bl_do_dc_option (TLS, id, l1, name, l2, ip, port);
}

static int help_get_config_on_answer (struct tgl_state *TLS, struct query *q) {
  unsigned op = fetch_int ();
  assert (op == CODE_config || op == CODE_config_old);
  fetch_int ();

  unsigned test_mode = fetch_int ();
  assert (test_mode == CODE_bool_true || test_mode == CODE_bool_false);
  assert (test_mode == CODE_bool_false || test_mode == CODE_bool_true);
  int this_dc = fetch_int ();
  vlogprintf (E_DEBUG, "this_dc = %d\n", this_dc);
  assert (fetch_int () == CODE_vector);
  int n = fetch_int ();
  assert (n <= 10);
  int i;
  for (i = 0; i < n; i++) {
    fetch_dc_option (TLS);
  }
  int max_chat_size = fetch_int ();
  int max_bcast_size = 0;
  if (op == CODE_config) {
    max_bcast_size = fetch_int ();
  }
  vlogprintf (E_DEBUG, "chat_size = %d, bcast_size = %d\n", max_chat_size, max_bcast_size);

  if (q->callback) {
    ((void (*)(struct tgl_state *,void *, int))(q->callback))(TLS, q->callback_extra, 1);
  }
  return 0;
}

static int q_void_on_error (struct tgl_state *TLS, struct query *q, int error_code, int error_len, const char *error) {
  if (q->callback) {
    ((void (*)(struct tgl_state *,void *, int))(q->callback))(TLS, q->callback_extra, 0);
  }
  return 0;
}

static int q_ptr_on_error (struct tgl_state *TLS, struct query *q, int error_code, int error_len, const char *error) {
  if (q->callback) {
    ((void (*)(struct tgl_state *,void *, int, void *))(q->callback))(TLS, q->callback_extra, 0, NULL);
  }
  return 0;
}

static int q_list_on_error (struct tgl_state *TLS, struct query *q, int error_code, int error_len, const char *error) {
  if (q->callback) {
    ((void (*)(struct tgl_state *,void *, int, int, void *))(q->callback))(TLS, q->callback_extra, 0, 0, NULL);
  }
  return 0;
}

static struct query_methods help_get_config_methods  = {
  .on_answer = help_get_config_on_answer,
  .on_error = q_void_on_error,
  .type = TYPE_TO_PARAM(config)
};

void tgl_do_help_get_config (struct tgl_state *TLS, void (*callback)(struct tgl_state *,void *, int), void *callback_extra) {
  clear_packet ();  
  tgl_do_insert_header (TLS);
  out_int (CODE_help_get_config);
  tglq_send_query (TLS, TLS->DC_working, packet_ptr - packet_buffer, packet_buffer, &help_get_config_methods, 0, callback, callback_extra);
}

void tgl_do_help_get_config_dc (struct tgl_state *TLS, struct tgl_dc *D, void (*callback)(struct tgl_state *, void *, int), void *callback_extra) {
  clear_packet ();  
  tgl_do_insert_header (TLS);
  out_int (CODE_help_get_config);
  tglq_send_query_ex (TLS, D, packet_ptr - packet_buffer, packet_buffer, &help_get_config_methods, 0, callback, callback_extra, 2);
}
/* }}} */

/* {{{ Send code */
static int send_code_on_answer (struct tgl_state *TLS, struct query *q) {
  static char *phone_code_hash;  
  assert (fetch_int () == (int)CODE_auth_sent_code);
  int registered = fetch_bool ();
  int l = prefetch_strlen ();
  char *s = fetch_str (l);
  if (phone_code_hash) {
    tfree_str (phone_code_hash);
  }
  phone_code_hash = tstrndup (s, l);
  fetch_int (); 
  fetch_bool ();
  tfree_str (q->extra);
  
  if (q->callback) {
    ((void (*)(struct tgl_state *, void *, int, int, const char *))(q->callback)) (TLS, q->callback_extra, 1, registered, phone_code_hash);
  }
  return 0;
}

static int send_code_on_error (struct tgl_state *TLS, struct query *q, int error_code, int l, const char *error) {
  if (q->callback) {
    ((void (*)(struct tgl_state *, void *, int, int, const char *))(q->callback)) (TLS, q->callback_extra, 0, 0, NULL);
  }
  tfree_str (q->extra);
  return 0;
}

static struct query_methods send_code_methods  = {
  .on_answer = send_code_on_answer,
  .on_error = send_code_on_error,
  .type = TYPE_TO_PARAM(auth_sent_code)
};

//char *suser;
//extern int dc_working_num;
void tgl_do_send_code (struct tgl_state *TLS, const char *user, void (*callback)(struct tgl_state *TLS, void *callback_extra, int success, int registered, const char *hash), void *callback_extra) {
  vlogprintf (E_DEBUG, "sending code to dc %d\n", TLS->dc_working_num);
  //suser = tstrdup (user);
  clear_packet ();
  tgl_do_insert_header (TLS);
  out_int (CODE_auth_send_code);
  out_string (user);
  out_int (0);
  out_int (TLS->app_id);
  out_string (TLS->app_hash);
  out_string ("en");

  tglq_send_query (TLS, TLS->DC_working, packet_ptr - packet_buffer, packet_buffer, &send_code_methods, tstrdup (user), callback, callback_extra);
}


static int phone_call_on_answer (struct tgl_state *TLS, struct query *q) {
  fetch_bool ();
  if (q->callback) {
    ((void (*)(struct tgl_state *TLS, void *, int))(q->callback))(TLS, q->callback_extra, 1);
  }
  return 0;
}

static struct query_methods phone_call_methods  = {
  .on_answer = phone_call_on_answer,
  .on_error = q_void_on_error,
  .type = TYPE_TO_PARAM(bool)
};

void tgl_do_phone_call (struct tgl_state *TLS, const char *user, const char *hash,void (*callback)(struct tgl_state *TLS, void *callback_extra, int success), void *callback_extra) {
  vlogprintf (E_DEBUG, "calling user\n");
  //suser = tstrdup (user);
  //want_dc_num = 0;
  clear_packet ();
  tgl_do_insert_header (TLS);
  out_int (CODE_auth_send_call);
  out_string (user);
  out_string (hash);

  tglq_send_query (TLS, TLS->DC_working, packet_ptr - packet_buffer, packet_buffer, &phone_call_methods, 0, callback, callback_extra);
}
/* }}} */

/* {{{ Sign in / Sign up */
static int sign_in_on_answer (struct tgl_state *TLS, struct query *q) {
  assert (fetch_int () == (int)CODE_auth_authorization);
  int expires = fetch_int ();
  vlogprintf (E_DEBUG, "Expires in %d\n", expires);

  struct tgl_user *U = tglf_fetch_alloc_user (TLS);
  
  //TLS->DC_working->has_auth = 1;
  bl_do_dc_signed (TLS, TLS->DC_working->id);

  if (q->callback) {
    ((void (*)(struct tgl_state *TLS, void *, int, struct tgl_user *))q->callback) (TLS, q->callback_extra, 1, U);
  }

  return 0;
}

static int sign_in_on_error (struct tgl_state *TLS, struct query *q, int error_code, int l, const char *error) {
    vlogprintf (E_ERROR, "error_code = %d, error = %.*s\n", error_code, l, error);
    if (q->callback) {
        ((void (*)(struct tgl_state *, void *, int, struct tgl_user *))q->callback) (TLS, q->callback_extra, 0, NULL);
    }
    return 0;
}

static struct query_methods sign_in_methods  = {
  .on_answer = sign_in_on_answer,
  .on_error = sign_in_on_error,
  .type = TYPE_TO_PARAM(auth_authorization)
};

int tgl_do_send_code_result (struct tgl_state *TLS, const char *user, const char *hash, const char *code, void (*callback)(struct tgl_state *TLS, void *callback_extra, int success, struct tgl_user *Self), void *callback_extra) {
  clear_packet ();
  out_int (CODE_auth_sign_in);
  out_string (user);
  out_string (hash);
  out_string (code);
  tglq_send_query (TLS, TLS->DC_working, packet_ptr - packet_buffer, packet_buffer, &sign_in_methods, 0, callback, callback_extra);
  return 0;
}

int tgl_do_send_code_result_auth (struct tgl_state *TLS, const char *user, const char *hash, const char *code, const char *first_name, const char *last_name, void (*callback)(struct tgl_state *TLS, void *callback_extra, int success, struct tgl_user *Self), void *callback_extra) {
  clear_packet ();
  out_int (CODE_auth_sign_up);
  out_string (user);
  out_string (hash);
  out_string (code);
  out_string (first_name);
  out_string (last_name);
  tglq_send_query (TLS, TLS->DC_working, packet_ptr - packet_buffer, packet_buffer, &sign_in_methods, 0, callback, callback_extra);
  return 0;
}
/* }}} */

/* {{{ Get contacts */
static int get_contacts_on_answer (struct tgl_state *TLS, struct query *q) {
  int i;

  assert (fetch_int () == (int)CODE_contacts_contacts);
  assert (fetch_int () == CODE_vector);
  int n = fetch_int ();
  for (i = 0; i < n; i++) {
    assert (fetch_int () == (int)CODE_contact);
    fetch_int (); // id
    fetch_int (); // mutual
  }
  assert (fetch_int () == CODE_vector);
  n = fetch_int ();
  struct tgl_user **list = talloc (sizeof (void *) * n);
  for (i = 0; i < n; i++) {
    list[i] = tglf_fetch_alloc_user (TLS);
  }
  if (q->callback) {
    ((void (*)(struct tgl_state *TLS, void *, int, int, struct tgl_user **))q->callback) (TLS, q->callback_extra, 1, n, list);  
  }
  tfree (list, sizeof (void *) * n); 
  return 0;
}

static struct query_methods get_contacts_methods = {
  .on_answer = get_contacts_on_answer,
  .on_error = q_list_on_error,
  .type = TYPE_TO_PARAM(contacts_contacts)
};


void tgl_do_update_contact_list (struct tgl_state *TLS, void (*callback) (struct tgl_state *TLS, void *callback_extra, int success, int size, struct tgl_user *contacts[]), void *callback_extra) {
  clear_packet ();
  out_int (CODE_contacts_get_contacts);
  out_string ("");
  tglq_send_query (TLS, TLS->DC_working, packet_ptr - packet_buffer, packet_buffer, &get_contacts_methods, 0, callback, callback_extra);
}
/* }}} */

/* {{{ Encrypt decrypted */
static int *encr_extra;
static int *encr_ptr;
static int *encr_end;

static char *encrypt_decrypted_message (struct tgl_secret_chat *E) {
  static int msg_key[4];
  static unsigned char sha1a_buffer[20];
  static unsigned char sha1b_buffer[20];
  static unsigned char sha1c_buffer[20];
  static unsigned char sha1d_buffer[20];
  int x = *(encr_ptr);  
  assert (x >= 0 && !(x & 3));
  sha1 ((void *)encr_ptr, 4 + x, sha1a_buffer);
  memcpy (msg_key, sha1a_buffer + 4, 16);
 
  static unsigned char buf[64];
  memcpy (buf, msg_key, 16);
  memcpy (buf + 16, E->key, 32);
  sha1 (buf, 48, sha1a_buffer);
  
  memcpy (buf, E->key + 8, 16);
  memcpy (buf + 16, msg_key, 16);
  memcpy (buf + 32, E->key + 12, 16);
  sha1 (buf, 48, sha1b_buffer);
  
  memcpy (buf, E->key + 16, 32);
  memcpy (buf + 32, msg_key, 16);
  sha1 (buf, 48, sha1c_buffer);
  
  memcpy (buf, msg_key, 16);
  memcpy (buf + 16, E->key + 24, 32);
  sha1 (buf, 48, sha1d_buffer);

  static unsigned char key[32];
  memcpy (key, sha1a_buffer + 0, 8);
  memcpy (key + 8, sha1b_buffer + 8, 12);
  memcpy (key + 20, sha1c_buffer + 4, 12);

  static unsigned char iv[32];
  memcpy (iv, sha1a_buffer + 8, 12);
  memcpy (iv + 12, sha1b_buffer + 0, 8);
  memcpy (iv + 20, sha1c_buffer + 16, 4);
  memcpy (iv + 24, sha1d_buffer + 0, 8);

  AES_KEY aes_key;
  AES_set_encrypt_key (key, 256, &aes_key);
  AES_ige_encrypt ((void *)encr_ptr, (void *)encr_ptr, 4 * (encr_end - encr_ptr), &aes_key, iv, 1);
  memset (&aes_key, 0, sizeof (aes_key));

  return (void *)msg_key;
}

static void encr_start (void) {
  encr_extra = packet_ptr;
  packet_ptr += 1; // str len
  packet_ptr += 2; // fingerprint
  packet_ptr += 4; // msg_key
  packet_ptr += 1; // len
}


static void encr_finish (struct tgl_secret_chat *E) {
  int l = packet_ptr - (encr_extra +  8);
  while (((packet_ptr - encr_extra) - 3) & 3) {  
    int t;
    tglt_secure_random (&t, 4);
    out_int (t);
  }

  *encr_extra = ((packet_ptr - encr_extra) - 1) * 4 * 256 + 0xfe;
  encr_extra ++;
  *(long long *)encr_extra = E->key_fingerprint;
  encr_extra += 2;
  encr_extra[4] = l * 4;
  encr_ptr = encr_extra + 4;
  encr_end = packet_ptr;
  memcpy (encr_extra, encrypt_decrypted_message (E), 16);
}
/* }}} */

void tgl_do_send_encr_chat_layer (struct tgl_state *TLS, struct tgl_secret_chat *E) {
  long long t;
  tglt_secure_random (&t, 8);
  int action[2];
  action[0] = CODE_decrypted_message_action_notify_layer;
  action[1] = TGL_ENCRYPTED_LAYER;
  bl_do_send_message_action_encr (TLS, t, TLS->our_id, tgl_get_peer_type (E->id), tgl_get_peer_id (E->id), time (0), 2, action);

  struct tgl_message *M = tgl_message_get (TLS, t);
  assert (M);
  assert (M->action.type == tgl_message_action_notify_layer);
  tgl_do_send_msg (TLS, M, 0, 0);
  //print_message (M);
}

void tgl_do_set_encr_chat_ttl (struct tgl_state *TLS, struct tgl_secret_chat *E, int ttl, void (*callback)(struct tgl_state *TLS, void *callback_extra, int success, struct tgl_message *M), void *callback_extra) {
  long long t;
  tglt_secure_random (&t, 8);
  int action[2];
  action[0] = CODE_decrypted_message_action_set_message_t_t_l;
  action[1] = ttl;
  bl_do_send_message_action_encr (TLS, t, TLS->our_id, tgl_get_peer_type (E->id), tgl_get_peer_id (E->id), time (0), 2, action);

  struct tgl_message *M = tgl_message_get (TLS, t);
  assert (M);
  assert (M->action.type == tgl_message_action_set_message_ttl);
  tgl_do_send_msg (TLS, M, callback, callback_extra);
  bl_do_encr_chat_set_ttl (TLS, E, ttl);
  //print_message (M);
}

/* {{{ Seng msg (plain text) */
static int msg_send_encr_on_answer (struct tgl_state *TLS, struct query *q) {
  assert (fetch_int () == CODE_messages_sent_encrypted_message);
  struct tgl_message *M = q->extra;
  //M->date = fetch_int ();
  fetch_int ();
  if (M->flags & FLAG_PENDING) {
    bl_do_set_message_sent (TLS, M);
    bl_do_msg_update (TLS, M->id);
  }

  if (q->callback) {
    ((void (*)(struct tgl_state *TLS, void *, int, struct tgl_message *))q->callback) (TLS, q->callback_extra, 1, M);
  }
  return 0;
}

static int msg_send_encr_on_error (struct tgl_state *TLS, struct query *q, int error_code, int error_len, const char *error) {
  struct tgl_message *M = q->extra;
  tgl_peer_t *P = tgl_peer_get (TLS, M->to_id);
  if (P && P->encr_chat.state != sc_deleted &&  error_code == 400) {
    if (strncmp (error, "ENCRYPTION_DECLINED", 19) == 0) {
      bl_do_encr_chat_delete(TLS, &P->encr_chat);
    }
  }
  if (q->callback) {
    ((void (*)(struct tgl_state *TLS, void *, int, struct tgl_message *))q->callback) (TLS, q->callback_extra, 0, M);
  }
  if (M) {
    bl_do_delete_msg (TLS, M);
  }
  return 0;
}

static int msg_send_on_answer (struct tgl_state *TLS, struct query *q) {
  unsigned x = fetch_int ();
  assert (x == CODE_messages_sent_message || x == CODE_messages_sent_message_link);
  int id = fetch_int (); // id
  long long y = *(long long *)q->extra;
  tfree (q->extra, 8);
  struct tgl_message *M = tgl_message_get (TLS, y);
  if (M && M->id != id) {
    bl_do_set_msg_id (TLS, M, id);
  }
  int date = fetch_int ();
  int pts = fetch_int ();
  int seq = fetch_int ();
  if (seq == TLS->seq + 1 && !(TLS->locks & TGL_LOCK_DIFF)) {
    bl_do_set_date (TLS, date);
    bl_do_set_pts (TLS, pts);
    bl_do_msg_seq_update (TLS, id);
  } else {
    if (seq > TLS->seq + 1) {
      vlogprintf (E_NOTICE, "Hole in seq\n");
      tgl_do_get_difference (TLS, 0, 0, 0);
    }
  }
  if (x == CODE_messages_sent_message_link) {
    assert (skip_type_any (TYPE_TO_PARAM_1 (vector, TYPE_TO_PARAM (contacts_link))) >= 0);
  }
  if (M->flags & FLAG_PENDING) {
    bl_do_set_message_sent (TLS, M);
  }
  if (q->callback) {
    ((void (*)(struct tgl_state *,void *, int, struct tgl_message *))q->callback) (TLS, q->callback_extra, 1, M);
  }
  return 0;
}

static int msg_send_on_error (struct tgl_state *TLS, struct query *q, int error_code, int error_len, const char *error) {
  //vlogprintf (E_WARNING, "error for query #%lld: #%d :%.*s\n", q->msg_id, error_code, error_len, error);
  long long x = *(long long *)q->extra;
  tfree (q->extra, 8);
  struct tgl_message *M = tgl_message_get (TLS, x);
  if (q->callback) {
    ((void (*)(struct tgl_state *,void *, int, struct tgl_message *))q->callback) (TLS, q->callback_extra, 0, M);
  }
  if (M) {
    bl_do_delete_msg (TLS, M);
  }
  return 0;
}

static struct query_methods msg_send_methods = {
  .on_answer = msg_send_on_answer,
  .on_error = msg_send_on_error,
  .type = TYPE_TO_PARAM(messages_sent_message)
};

static struct query_methods msg_send_encr_methods = {
  .on_answer = msg_send_encr_on_answer,
  .on_error = msg_send_encr_on_error,
  .type = TYPE_TO_PARAM(messages_sent_encrypted_message)
};

//int out_message_num;

void tgl_do_send_encr_msg_action (struct tgl_state *TLS, struct tgl_message *M, void (*callback)(struct tgl_state *TLS, void *callback_extra, int success, struct tgl_message *M), void *callback_extra) {
  tgl_peer_t *P = tgl_peer_get (TLS, M->to_id);
  if (!P || P->encr_chat.state != sc_ok) { 
    vlogprintf (E_WARNING, "Unknown encrypted chat\n");
    if (callback) {
      callback (TLS, callback_extra, 0, 0);
    }
    return;
  }
  
  clear_packet ();
  out_int (CODE_messages_send_encrypted_service);
  out_int (CODE_input_encrypted_chat);
  out_int (tgl_get_peer_id (M->to_id));
  out_long (P->encr_chat.access_hash);
  out_long (M->id);
  encr_start ();
  if (P->encr_chat.layer <= 16) {
    out_int (CODE_decrypted_message_service_l16);
  } else {
    out_int (CODE_decrypted_message_layer);
    out_random (15 + 4 * (lrand48 () % 3));
    out_int (TGL_ENCRYPTED_LAYER);
    out_int (2 * P->encr_chat.in_seq_no + (P->encr_chat.admin_id != TLS->our_id));
    out_int (2 * P->encr_chat.out_seq_no + (P->encr_chat.admin_id == TLS->our_id) - 2);
    out_int (CODE_decrypted_message_service);
  }
  out_long (M->id);
  if (P->encr_chat.layer < 17) {
    out_random (15 + 4 * (lrand48 () % 3));
  }

  switch (M->action.type) {
  case tgl_message_action_notify_layer:
    out_int (CODE_decrypted_message_action_notify_layer);
    out_int (M->action.layer);
    break;
  case tgl_message_action_set_message_ttl:
    out_int (CODE_decrypted_message_action_set_message_t_t_l);
    out_int (M->action.ttl);
    break;
  case tgl_message_action_request_key:
    out_int (CODE_decrypted_message_action_request_key);
    out_long (M->action.exchange_id);
    out_cstring ((void *)M->action.g_a, 256);
    break;
  case tgl_message_action_accept_key:
    out_int (CODE_decrypted_message_action_accept_key);
    out_long (M->action.exchange_id);
    out_cstring ((void *)M->action.g_a, 256);    
    out_long (M->action.key_fingerprint);
    break;
  case tgl_message_action_commit_key:
    out_int (CODE_decrypted_message_action_commit_key);
    out_long (M->action.exchange_id);
    out_long (M->action.key_fingerprint);
    break;
  case tgl_message_action_abort_key:
    out_int (CODE_decrypted_message_action_abort_key);
    out_long (M->action.exchange_id);
    break;
  case tgl_message_action_noop:
    out_int (CODE_decrypted_message_action_noop);
    break;
  default:
    assert (0);
  }
  encr_finish (&P->encr_chat);
  
  tglq_send_query (TLS, TLS->DC_working, packet_ptr - packet_buffer, packet_buffer, &msg_send_encr_methods, M, callback, callback_extra);
}

void tgl_do_send_encr_msg (struct tgl_state *TLS, struct tgl_message *M, void (*callback)(struct tgl_state *TLS, void *callback_extra, int success, struct tgl_message *M), void *callback_extra) {
  if (M->service) {
    tgl_do_send_encr_msg_action (TLS, M, callback, callback_extra);
    return;
  }
  tgl_peer_t *P = tgl_peer_get (TLS, M->to_id);
  if (!P || P->encr_chat.state != sc_ok) { 
    vlogprintf (E_WARNING, "Unknown encrypted chat\n");
    if (callback) {
      callback (TLS, callback_extra, 0, M);
    }
    return;
  }
  
  clear_packet ();
  out_int (CODE_messages_send_encrypted);
  out_int (CODE_input_encrypted_chat);
  out_int (tgl_get_peer_id (M->to_id));
  out_long (P->encr_chat.access_hash);
  out_long (M->id);
  encr_start ();
  if (P->encr_chat.layer <= 16) {
    out_int (CODE_decrypted_message_l16);
  } else {
    out_int (CODE_decrypted_message_layer);
    out_random (15 + 4 * (lrand48 () % 3));
    out_int (TGL_ENCRYPTED_LAYER);
    out_int (2 * P->encr_chat.in_seq_no + (P->encr_chat.admin_id != TLS->our_id));
    out_int (2 * P->encr_chat.out_seq_no + (P->encr_chat.admin_id == TLS->our_id) - 2);
    out_int (CODE_decrypted_message);
  }
  out_long (M->id);
  if (P->encr_chat.layer < 17) {
    out_random (15 + 4 * (lrand48 () % 3));
  } else {
    out_int (P->encr_chat.ttl);
  }
  out_cstring ((void *)M->message, M->message_len);
  out_int (CODE_decrypted_message_media_empty);
  encr_finish (&P->encr_chat);
  
  tglq_send_query (TLS, TLS->DC_working, packet_ptr - packet_buffer, packet_buffer, &msg_send_encr_methods, M, callback, callback_extra);
}

void tgl_do_send_msg (struct tgl_state *TLS, struct tgl_message *M, void (*callback)(struct tgl_state *TLS, void *callback_extra, int success, struct tgl_message *M), void *callback_extra) {
  if (tgl_get_peer_type (M->to_id) == TGL_PEER_ENCR_CHAT) {
    tgl_do_send_encr_msg (TLS, M, callback, callback_extra);
    return;
  }
  clear_packet ();
  out_int (CODE_messages_send_message);
  out_peer_id (TLS, M->to_id);
  out_cstring (M->message, M->message_len);
  out_long (M->id);
  long long *x = talloc (8);
  *x = M->id;
  tglq_send_query (TLS, TLS->DC_working, packet_ptr - packet_buffer, packet_buffer, &msg_send_methods, x, callback, callback_extra);
}

void tgl_do_send_message (struct tgl_state *TLS, tgl_peer_id_t id, const char *msg, int len, void (*callback)(struct tgl_state *TLS, void *callback_extra, int success, struct tgl_message *M), void *callback_extra) {
  if (tgl_get_peer_type (id) == TGL_PEER_ENCR_CHAT) {
    tgl_peer_t *P = tgl_peer_get (TLS, id);
    if (!P) {
      vlogprintf (E_WARNING, "Unknown encrypted chat\n");
      if (callback) {
        callback (TLS, callback_extra, 0, 0);
      }
      return;
    }
    if (P->encr_chat.state != sc_ok) {
      vlogprintf (E_WARNING, "Chat is not yet initialized\n");
      if (callback) {
        callback (TLS, callback_extra, 0, 0);
      }
      return;
    }
  }
  long long t;
  tglt_secure_random (&t, 8);
  vlogprintf (E_DEBUG, "t = %lld, len = %d\n", t, len);
  bl_do_send_message_text (TLS, t, TLS->our_id, tgl_get_peer_type (id), tgl_get_peer_id (id), time (0), len, msg);
  struct tgl_message *M = tgl_message_get (TLS, t);
  assert (M);
  tgl_do_send_msg (TLS, M, callback, callback_extra);
  //print_message (M);
}
/* }}} */

/* {{{ Send text file */
void tgl_do_send_text (struct tgl_state *TLS, tgl_peer_id_t id, const char *file_name, void (*callback)(struct tgl_state *TLS, void *callback_extra, int success, struct tgl_message *M), void *callback_extra) {
  int fd = open (file_name, O_RDONLY);
  if (fd < 0) {
    vlogprintf (E_WARNING, "No such file '%s'\n", file_name);
    if (callback) {
      callback (TLS, callback_extra, 0, 0);
    }
    return;
  }
  static char buf[(1 << 20) + 1];
  int x = read (fd, buf, (1 << 20) + 1);
  assert (x >= 0);
  if (x == (1 << 20) + 1) {
    vlogprintf (E_WARNING, "Too big file '%s'\n", file_name);
    close (fd);
    if (callback) {
      callback (TLS, callback_extra, 0, 0);
    }
  } else {
    buf[x] = 0;
    tgl_do_send_message (TLS, id, buf, x, callback, callback_extra);
    //tfree_str (file_name);
    close (fd);
  }
}
/* }}} */

/* {{{ Mark read */
void tgl_do_messages_mark_read (struct tgl_state *TLS, tgl_peer_id_t id, int max_id, int offset, void (*callback)(struct tgl_state *TLS, void *callback_extra, int), void *callback_extra);
static int mark_read_on_receive (struct tgl_state *TLS, struct query *q) {
  assert (fetch_int () == (int)CODE_messages_affected_history);
  //tglu_fetch_pts ();
  int pts = fetch_int ();
  //tglu_fetch_seq ();
  int seq = fetch_int (); // seq

  if (seq == TLS->seq + 1 && !(TLS->locks & TGL_LOCK_DIFF)) {
    bl_do_set_pts (TLS, pts);
    bl_do_set_seq (TLS, seq);
  } else {
    if (seq > TLS->seq + 1) {
      vlogprintf (E_NOTICE, "Hole in seq\n");
      tgl_do_get_difference (TLS, 0, 0, 0);
    }
  }

  int offset = fetch_int (); // offset
  int *t = q->extra;
  if (offset > 0) {
    tgl_do_messages_mark_read (TLS, tgl_set_peer_id (t[0], t[1]), t[2], offset, q->callback, q->callback_extra);
  } else {
    if (q->callback) {
      ((void (*)(struct tgl_state *, void *, int))q->callback)(TLS, q->callback_extra, 1);
    }
  }
  tfree (t, 12);
  return 0;
}

static int mark_read_on_error (struct tgl_state *TLS, struct query *q, int error_code, int len, const char *error) {
  int *t = q->extra;
  tfree (t, 12);
  if (q->callback) {
    ((void (*)(struct tgl_state *, void *, int))q->callback)(TLS, q->callback_extra, 0);
  }
  return 0;
}

static int mark_read_encr_on_receive (struct tgl_state *TLS, struct query *q) {
  fetch_bool ();
  if (q->callback) {
    ((void (*)(struct tgl_state *, void *, int))q->callback)(TLS, q->callback_extra, 1);
  }
  return 0;
}

static int mark_read_encr_on_error (struct tgl_state *TLS, struct query *q, int error_code, int error_len, const char *error) {
  tgl_peer_t *P = q->extra;
  if (P && P->encr_chat.state != sc_deleted &&  error_code == 400) {
    if (strncmp (error, "ENCRYPTION_DECLINED", 19) == 0) {
      bl_do_encr_chat_delete(TLS, &P->encr_chat);
    }
  }
  return 0;
}

static struct query_methods mark_read_methods = {
  .on_answer = mark_read_on_receive,
  .on_error = mark_read_on_error,
  .type = TYPE_TO_PARAM(messages_affected_history)
};

static struct query_methods mark_read_encr_methods = {
  .on_answer = mark_read_encr_on_receive,
  .on_error = mark_read_encr_on_error,
  .type = TYPE_TO_PARAM(bool)
};

void tgl_do_messages_mark_read (struct tgl_state *TLS, tgl_peer_id_t id, int max_id, int offset, void (*callback)(struct tgl_state *TLS, void *callback_extra, int), void *callback_extra) {
  clear_packet ();
  out_int (CODE_messages_read_history);
  out_peer_id (TLS, id);
  out_int (max_id);
  out_int (offset);
  out_int (CODE_bool_true);
  int *t = talloc (12);
  t[0] = tgl_get_peer_type (id);
  t[1] = tgl_get_peer_id (id);
  t[2] = max_id;
  tglq_send_query (TLS, TLS->DC_working, packet_ptr - packet_buffer, packet_buffer, &mark_read_methods, t, callback, callback_extra);
}

void tgl_do_messages_mark_read_encr (struct tgl_state *TLS, tgl_peer_id_t id, long long access_hash, int last_time, void (*callback)(struct tgl_state *TLS, void *callback_extra, int), void *callback_extra) {
  clear_packet ();
  out_int (CODE_messages_read_encrypted_history);
  out_int (CODE_input_encrypted_chat);
  out_int (tgl_get_peer_id (id));
  out_long (access_hash);
  out_int (last_time);
  tglq_send_query (TLS, TLS->DC_working, packet_ptr - packet_buffer, packet_buffer, &mark_read_encr_methods, tgl_peer_get (TLS, id), callback, callback_extra);
}

void tgl_do_mark_read (struct tgl_state *TLS, tgl_peer_id_t id, void (*callback)(struct tgl_state *TLS, void *callback_extra, int success), void *callback_extra) {
  if (tgl_get_peer_type (id) == TGL_PEER_USER || tgl_get_peer_type (id) == TGL_PEER_CHAT) {
    tgl_do_messages_mark_read (TLS, id, 0, 0, callback, callback_extra);
    return;
  }
  tgl_peer_t *P = tgl_peer_get (TLS, id);
  if (!P) {
    vlogprintf (E_WARNING, "Unknown peer\n");
    callback (TLS, callback_extra, 0);
    return;
  }
  assert (tgl_get_peer_type (id) == TGL_PEER_ENCR_CHAT);
  if (P->last) {
    tgl_do_messages_mark_read_encr (TLS, id, P->encr_chat.access_hash, P->last->date, callback, callback_extra);
  } else {
    tgl_do_messages_mark_read_encr (TLS, id, P->encr_chat.access_hash, time (0) - 10, callback, callback_extra);
    
  }
}
/* }}} */

/* {{{ Get history */
void _tgl_do_get_history (struct tgl_state *TLS, tgl_peer_id_t id, int limit, int offset, int max_id, int list_offset, int list_size, struct tgl_message *ML[], void (*callback)(struct tgl_state *TLS,void *callback_extra, int success, int size, struct tgl_message *list[]), void *callback_extra);
static int get_history_on_answer (struct tgl_state *TLS, struct query *q) {
  int count = -1;
  int i;
  int x = fetch_int ();
  assert (x == (int)CODE_messages_messages_slice || x == (int)CODE_messages_messages);
  if (x == (int)CODE_messages_messages_slice) {
    count = fetch_int ();
    //fetch_int ();
  }
  assert (fetch_int () == CODE_vector);
  void **T = q->extra;
  struct tgl_message **ML = T[0];
  int list_offset = (long)T[1];
  int list_size = (long)T[2];
  tgl_peer_id_t id = tgl_set_peer_id ((long)T[4], (long)T[3]);
  int limit = (long)T[5];
  int offset = (long)T[6];
  tfree (T, sizeof (void *) * 7);
  
  int n = fetch_int ();

  if (list_size - list_offset < n) {
    int new_list_size = 2 * list_size;
    if (new_list_size - list_offset < n) {
      new_list_size = n + list_offset;
    }
    ML = trealloc (ML, list_size * sizeof (void *), new_list_size * sizeof (void *));
    assert (ML);
    list_size = new_list_size;
  }
  //struct tgl_message **ML = talloc (sizeof (void *) * n);
  for (i = 0; i < n; i++) {
    ML[i + list_offset] = tglf_fetch_alloc_message (TLS);
  }
  list_offset += n;
  offset += n;
  limit -= n;
  if (count >= 0 && limit + offset >= count) {
    limit = count - offset;
    if (limit < 0) { limit = 0; }
  }
  assert (limit >= 0);
  
  assert (fetch_int () == CODE_vector);
  n = fetch_int ();
  for (i = 0; i < n; i++) {
    tglf_fetch_alloc_chat (TLS);
  }
  assert (fetch_int () == CODE_vector);
  n = fetch_int ();
  for (i = 0; i < n; i++) {
    tglf_fetch_alloc_user (TLS);
  }

 
  if (limit <= 0 || x == (int)CODE_messages_messages) {
    if (q->callback) {
      ((void (*)(struct tgl_state *TLS, void *, int, int, struct tgl_message **))q->callback) (TLS, q->callback_extra, 1, list_offset, ML);
    }
    if (list_offset > 0) {
      tgl_do_messages_mark_read (TLS, id, ML[0]->id, 0, 0, 0);
    }

  
    tfree (ML, sizeof (void *) * list_size);
  } else {
   _tgl_do_get_history (TLS, id, limit, 0, ML[list_offset - 1]->id, list_offset, list_size, ML, q->callback, q->callback_extra);
  }
  return 0;
}

static int get_history_on_error (struct tgl_state *TLS, struct query *q, int error_code, int error_len, const char *error) {
  void **T = q->extra;
  struct tgl_message **ML = T[0];
  int list_size = (long)T[2];
  tfree (T, sizeof (void *) * 7);
  tfree (ML, sizeof (void *) * list_size);

  if (q->callback) {
    ((void (*)(struct tgl_state *TLS, void *, int, int, struct tgl_message **))q->callback) (TLS, q->callback_extra, 0, 0, NULL);
  }
  return 0;
}

static struct query_methods get_history_methods = {
  .on_answer = get_history_on_answer,
  .on_error = get_history_on_error,
  .type = TYPE_TO_PARAM(messages_messages)
};

void tgl_do_get_local_history (struct tgl_state *TLS, tgl_peer_id_t id, int limit, void (*callback)(struct tgl_state *TLS, void *callback_extra, int success, int size, struct tgl_message *list[]), void *callback_extra) {
  tgl_peer_t *P = tgl_peer_get (TLS, id);
  if (!P || !P->last) { 
    if (callback) {
      callback (TLS, callback_extra, 0, 0, 0);
    }
    return; 
  }
  struct tgl_message *M = P->last;
  int count = 1;
  assert (!M->prev);
  while (count < limit && M->next) {
    M = M->next;
    count ++;
  }
  struct tgl_message **ML = talloc (sizeof (void *) * count);
  M = P->last;
  ML[0] = M;
  count = 1;
  while (count < limit && M->next) {
    M = M->next;
    ML[count ++] = M;
  }

  if (callback) {
    callback (TLS, callback_extra, 1, count, ML);
  }
  tfree (ML, sizeof (void *) * count);
}

void tgl_do_get_local_history_ext (struct tgl_state *TLS, tgl_peer_id_t id, int offset, int limit, void (*callback)(struct tgl_state *TLS,void *callback_extra, int success, int size, struct tgl_message *list[]), void *callback_extra) {
  tgl_peer_t *P = tgl_peer_get (TLS, id);
  if (!P || !P->last) { 
    if (callback) {
      callback (TLS, callback_extra, 0, 0, 0);
    }
    return; 
  }
  struct tgl_message *M = P->last;
  int count = 1;
  assert (!M->prev);
  while (count < limit + offset && M->next) {
    M = M->next;
    count ++;
  }
  if (count <= offset) {
    if (callback) {
      callback (TLS, callback_extra, 1, 0, 0);
    }
    return;
  }
  struct tgl_message **ML = talloc (sizeof (void *) * (count - offset));
  M = P->last;
  ML[0] = M;
  count = 1;
  while (count < limit && M->next) {
    M = M->next;
    if (count >= offset) {
      ML[count - offset] = M;
    }
    count ++;
  }

  if (callback) {
    callback (TLS, callback_extra, 1, count - offset, ML);
  }
  tfree (ML, sizeof (void *) * (count) - offset);
}



void _tgl_do_get_history (struct tgl_state *TLS, tgl_peer_id_t id, int limit, int offset, int max_id, int list_offset, int list_size, struct tgl_message *ML[], void (*callback)(struct tgl_state *TLS,void *callback_extra, int success, int size, struct tgl_message *list[]), void *callback_extra) {
  void **T = talloc (sizeof (void *) * 7);
  T[0] = ML;
  T[1] = (void *)(long)list_offset;
  T[2] = (void *)(long)list_size;
  T[3] = (void *)(long)tgl_get_peer_id (id);
  T[4] = (void *)(long)tgl_get_peer_type (id);
  T[5] = (void *)(long)limit;
  T[6] = (void *)(long)offset;

  clear_packet ();
  out_int (CODE_messages_get_history);
  out_peer_id (TLS, id);
  out_int (offset);
  out_int (max_id);
  out_int (limit);
  tglq_send_query (TLS, TLS->DC_working, packet_ptr - packet_buffer, packet_buffer, &get_history_methods, T, callback, callback_extra);
}

void tgl_do_get_history (struct tgl_state *TLS, tgl_peer_id_t id, int limit, int offline_mode, void (*callback)(struct tgl_state *TLS, void *callback_extra, int success, int size, struct tgl_message *list[]), void *callback_extra) {
  if (tgl_get_peer_type (id) == TGL_PEER_ENCR_CHAT || offline_mode) {
    tgl_do_get_local_history (TLS, id, limit, callback, callback_extra);
    tgl_do_mark_read (TLS, id, 0, 0);
    return;
  }
  _tgl_do_get_history (TLS, id, limit, 0, 0, 0, 0, 0, callback, callback_extra);
}

void tgl_do_get_history_ext (struct tgl_state *TLS, tgl_peer_id_t id, int offset, int limit, int offline_mode, void (*callback)(struct tgl_state *TLS, void *callback_extra, int success, int size, struct tgl_message *list[]), void *callback_extra) {
  if (tgl_get_peer_type (id) == TGL_PEER_ENCR_CHAT || offline_mode) {
    tgl_do_get_local_history (TLS, id, limit, callback, callback_extra);
    tgl_do_mark_read (TLS, id, 0, 0);
    return;
  }
  _tgl_do_get_history (TLS, id, limit, offset, 0, 0, 0, 0, callback, callback_extra);
}
/* }}} */

/* {{{ Get dialogs */
static int get_dialogs_on_answer (struct tgl_state *TLS, struct query *q) {
  unsigned x = fetch_int (); 
  assert (x == CODE_messages_dialogs || x == CODE_messages_dialogs_slice);
  if (x == CODE_messages_dialogs_slice) {
    fetch_int (); // total_count
  }
  assert (fetch_int () == CODE_vector);
  int n, i;
  n = fetch_int ();
  int dl_size = n;

  tgl_peer_id_t *PL = talloc0 (sizeof (tgl_peer_id_t) * n);
  int *UC = talloc0 (4 * n);
  int *LM = talloc0 (4 * n);
  for (i = 0; i < n; i++) {
    assert (fetch_int () == (int)CODE_dialog);
    PL[i] = tglf_fetch_peer_id (TLS);
    LM[i] = fetch_int ();
    UC[i] = fetch_int ();
    assert (skip_type_any (TYPE_TO_PARAM (peer_notify_settings)) >= 0);
  }
  assert (fetch_int () == CODE_vector);
  n = fetch_int ();
  for (i = 0; i < n; i++) {
    tglf_fetch_alloc_message (TLS);
  }
  assert (fetch_int () == CODE_vector);
  n = fetch_int ();
  for (i = 0; i < n; i++) {
    tglf_fetch_alloc_chat (TLS);
  }
  assert (fetch_int () == CODE_vector);
  n = fetch_int ();
  for (i = 0; i < n; i++) {
    tglf_fetch_alloc_user (TLS);
  }

  if (q->callback) {
    ((void (*)(struct tgl_state *TLS, void *, int, int, tgl_peer_id_t *, int *, int *))q->callback) (TLS, q->callback_extra, 1, dl_size, PL, LM, UC);
  }
  tfree (PL, sizeof (tgl_peer_id_t) * dl_size);
  tfree (UC, 4 * dl_size);
  tfree (LM, 4 * dl_size);
  
  return 0;
}

static int get_dialogs_on_error (struct tgl_state *TLS, struct query *q, int error_code, int error_len, const char *error) {
  if (q->callback) {
    ((void (*)(struct tgl_state *TLS, void *, int, int, tgl_peer_id_t *, int *, int *))q->callback) (TLS, q->callback_extra, 0, 0, NULL, NULL, NULL);
  }
  return 0;
}

static struct query_methods get_dialogs_methods = {
  .on_answer = get_dialogs_on_answer,
  .on_error = get_dialogs_on_error,
  .type = TYPE_TO_PARAM(messages_dialogs)
};


void tgl_do_get_dialog_list (struct tgl_state *TLS, void (*callback)(struct tgl_state *TLS, void *callback_extra, int success, int size, tgl_peer_id_t peers[], int last_msg_id[], int unread_count[]), void *callback_extra) {
  clear_packet ();
  out_int (CODE_messages_get_dialogs);
  out_int (0);
  out_int (0);
  out_int (1000);
  tglq_send_query (TLS, TLS->DC_working, packet_ptr - packet_buffer, packet_buffer, &get_dialogs_methods, 0, callback, callback_extra);
}
/* }}} */

int allow_send_linux_version = 1;

/* {{{ Send document file */
struct send_file {
  int fd;
  long long size;
  long long offset;
  int part_num;
  int part_size;
  long long id;
  long long thumb_id;
  tgl_peer_id_t to_id;
  int flags;
  char *file_name;
  int encr;
  int avatar;
  unsigned char *iv;
  unsigned char *init_iv;
  unsigned char *key;
  int w;
  int h;
  int duration;
};

static void out_peer_id (struct tgl_state *TLS, tgl_peer_id_t id) {
  tgl_peer_t *U;
  switch (tgl_get_peer_type (id)) {
  case TGL_PEER_CHAT:
    out_int (CODE_input_peer_chat);
    out_int (tgl_get_peer_id (id));
    break;
  case TGL_PEER_USER:
    U = tgl_peer_get (TLS, id);
    if (U && U->user.access_hash) {
      out_int (CODE_input_peer_foreign);
      out_int (tgl_get_peer_id (id));
      out_long (U->user.access_hash);
    } else {
      out_int (CODE_input_peer_contact);
      out_int (tgl_get_peer_id (id));
    }
    break;
  default:
    assert (0);
  }
}

static void send_part (struct tgl_state *TLS, struct send_file *f, void *callback, void *callback_extra);
static int send_file_part_on_answer (struct tgl_state *TLS, struct query *q) {
  assert (fetch_int () == (int)CODE_bool_true);
  send_part (TLS, q->extra, q->callback, q->callback_extra);
  return 0;
}

static int send_file_on_answer (struct tgl_state *TLS, struct query *q) {
  assert (fetch_int () == (int)CODE_messages_stated_message);
  struct tgl_message *M = tglf_fetch_alloc_message (TLS);
  assert (fetch_int () == CODE_vector);
  int n, i;
  n = fetch_int ();
  for (i = 0; i < n; i++) {
    tglf_fetch_alloc_chat (TLS);
  }
  assert (fetch_int () == CODE_vector);
  n = fetch_int ();
  for (i = 0; i < n; i++) {
    tglf_fetch_alloc_user (TLS);
  }
  //tglu_fetch_pts ();
  int pts = fetch_int ();
  //tglu_fetch_seq ();
  
  bl_do_msg_set_outbound (TLS, M->id);
  int seq = fetch_int ();
  if (seq == TLS->seq + 1 && !(TLS->locks & TGL_LOCK_DIFF)) {
    bl_do_set_pts (TLS, pts);
    bl_do_msg_seq_update (TLS, M->id);
  } else {
    if (seq > TLS->seq + 1) {
      vlogprintf (E_NOTICE, "Hole in seq\n");
      tgl_do_get_difference (TLS, 0, 0, 0);
    }
  }

  if (q->callback) {
    ((void (*)(struct tgl_state *, void *, int, struct tgl_message *))q->callback)(TLS, q->callback_extra, 1, M);
  }
  //print_message (M);
  return 0;
}

static int send_encr_file_on_answer (struct tgl_state *TLS, struct query *q) {
  assert (fetch_int () == (int)CODE_messages_sent_encrypted_file);
  struct tgl_message *M = q->extra;
  //M->date = fetch_int ();
  fetch_int ();
  int *save = in_ptr;

  assert (skip_type_any (TYPE_TO_PARAM (encrypted_file)) >= 0);
  
  //print_message (M);
  if (M->flags & FLAG_PENDING) {
    bl_do_create_message_media_encr_sent (TLS, M->id, save, in_ptr - save);
    //bl_do_set_message_sent (M);
    bl_do_msg_update (TLS, M->id);
  }
  
  if (q->callback) {
    ((void (*)(struct tgl_state *, void *, int, struct tgl_message *))q->callback)(TLS, q->callback_extra, 1, M);
  }
  return 0;
}

static int set_photo_on_answer (struct tgl_state *TLS, struct query *q) {
  assert (skip_type_any (TYPE_TO_PARAM(photos_photo)) >= 0);
  if (q->callback) {
    ((void (*)(struct tgl_state *, void *, int))q->callback)(TLS, q->callback_extra, 1);
  }
  return 0;
}

static int send_file_part_on_error (struct tgl_state *TLS, struct query *q, int error_code, int error_len, const char *error) {
  struct send_file *f = q->extra;   
  tfree_str (f->file_name);
  tfree (f, sizeof (*f));
  if (q->callback) {
    ((void (*)(struct tgl_state *, void *, int))q->callback)(TLS, q->callback_extra, 0);
  }
  return 0;
}

static struct query_methods send_file_part_methods = {
  .on_answer = send_file_part_on_answer,
  .on_error = send_file_part_on_error,
  .type = TYPE_TO_PARAM(bool)
};

static struct query_methods send_file_methods = {
  .on_answer = send_file_on_answer,
  .on_error = q_ptr_on_error,
  .type = TYPE_TO_PARAM(messages_stated_message)
};

static struct query_methods set_photo_methods = {
  .on_answer = set_photo_on_answer,
  .on_error = q_void_on_error,
  .type = TYPE_TO_PARAM(photos_photo)
};

static struct query_methods send_encr_file_methods = {
  .on_answer = send_encr_file_on_answer,
  .on_error = msg_send_encr_on_error,
  .type = TYPE_TO_PARAM(messages_sent_encrypted_message)
};

static void send_avatar_end (struct tgl_state *TLS, struct send_file *f, void *callback, void *callback_extra) {
  if (f->avatar > 0) {
    out_int (CODE_messages_edit_chat_photo);
    out_int (f->avatar);
    out_int (CODE_input_chat_uploaded_photo);
    if (f->size < (16 << 20)) {
      out_int (CODE_input_file);
    } else {
      out_int (CODE_input_file_big);
    }
    out_long (f->id);
    out_int (f->part_num);
    out_string ("");
    if (f->size < (16 << 20)) {
      out_string ("");
    }
    out_int (CODE_input_photo_crop_auto);
    tglq_send_query (TLS, TLS->DC_working, packet_ptr - packet_buffer, packet_buffer, &send_file_methods, 0, callback, callback_extra);
  } else {
    out_int (CODE_photos_upload_profile_photo);
    if (f->size < (16 << 20)) {
      out_int (CODE_input_file);
    } else {
      out_int (CODE_input_file_big);
    }
    out_long (f->id);
    out_int (f->part_num);
    char *s = f->file_name + strlen (f->file_name);
    while (s >= f->file_name && *s != '/') { s --;}
    out_string (s + 1);
    if (f->size < (16 << 20)) {
      out_string ("");
    }
    out_string ("profile photo");
    out_int (CODE_input_geo_point_empty);
    out_int (CODE_input_photo_crop_auto);
    tglq_send_query (TLS, TLS->DC_working, packet_ptr - packet_buffer, packet_buffer, &set_photo_methods, 0, callback, callback_extra);
  }
}


static void send_file_unencrypted_end (struct tgl_state *TLS, struct send_file *f, void *callback, void *callback_extra) {
  out_int (CODE_messages_send_media);
  out_peer_id (TLS, f->to_id);
  if (f->flags == -1) {
    out_int (CODE_input_media_uploaded_photo);
  } else {
    if (f->thumb_id > 0) {
      out_int (CODE_input_media_uploaded_thumb_document);
    } else {
      out_int (CODE_input_media_uploaded_document);
    }
  }

  if (f->size < (16 << 20)) {
    out_int (CODE_input_file);
  } else {
    out_int (CODE_input_file_big);
  }

  out_long (f->id);
  out_int (f->part_num);
  char *s = f->file_name + strlen (f->file_name);
  while (s >= f->file_name && *s != '/') { s --;}
  out_string (s + 1);
  if (f->size < (16 << 20)) {
    out_string ("");
  }

  if (f->flags != -1) {
    out_string (tg_mime_by_filename (f->file_name));

    out_int (CODE_vector);
    if (f->flags & FLAG_DOCUMENT_IMAGE) {
      if (f->flags & FLAG_DOCUMENT_ANIMATED) {
        out_int (2);
        out_int (CODE_document_attribute_image_size);
        out_int (f->w);
        out_int (f->h);
        out_int (CODE_document_attribute_animated);
      } else {
        out_int (2);
        out_int (CODE_document_attribute_image_size);
        out_int (f->w);
        out_int (f->h);
      }
    } else if (f->flags & FLAG_DOCUMENT_AUDIO) {
      out_int (1);
      out_int (CODE_document_attribute_audio);
      out_int (f->duration);
    } else if (f->flags & FLAG_DOCUMENT_VIDEO) {
      out_int (1);
      out_int (CODE_document_attribute_video);
      out_int (f->duration);
      out_int (f->w);
      out_int (f->h);
    } else if (f->flags & FLAG_DOCUMENT_STICKER) {
      out_int (1);
      out_int (CODE_document_attribute_sticker);
    } else {
      out_int (0);
    }

    if (f->thumb_id > 0) {
      out_int (CODE_input_file);
      out_long (f->thumb_id);
      out_int (1);
      out_string ("thumb.jpg");
      out_string ("");
    }
  }
  long long r;
  tglt_secure_random (&r, 8);
  out_long (r);
  tglq_send_query (TLS, TLS->DC_working, packet_ptr - packet_buffer, packet_buffer, &send_file_methods, 0, callback, callback_extra);
  tfree_str (f->file_name);
  tfree (f, sizeof (*f));
}

static void send_file_encrypted_end (struct tgl_state *TLS, struct send_file *f, void *callback, void *callback_extra) {
  out_int (CODE_messages_send_encrypted_file);
  out_int (CODE_input_encrypted_chat);
  out_int (tgl_get_peer_id (f->to_id));
  tgl_peer_t *P = tgl_peer_get (TLS, f->to_id);
  assert (P);
  out_long (P->encr_chat.access_hash);
  long long r;
  tglt_secure_random (&r, 8);
  out_long (r);
  encr_start ();
  if (P->encr_chat.layer <= 16) {
    out_int (CODE_decrypted_message_l16);
  } else {
    out_int (CODE_decrypted_message_layer);
    out_random (15 + 4 * (lrand48 () % 3));
    out_int (TGL_ENCRYPTED_LAYER);
    out_int (2 * P->encr_chat.in_seq_no + (P->encr_chat.admin_id != TLS->our_id));
    out_int (2 * P->encr_chat.out_seq_no + (P->encr_chat.admin_id == TLS->our_id));
    out_int (CODE_decrypted_message);
  }
  out_long (r);
  if (P->encr_chat.layer < 17) {
    out_random (15 + 4 * (lrand48 () % 3));
  } else {
    out_int (P->encr_chat.ttl);
  }
  out_string ("");
  int *save_ptr = packet_ptr;
  if (f->flags == -1) {
    out_int (CODE_decrypted_message_media_photo);
  } else if ((f->flags & FLAG_DOCUMENT_VIDEO)) {
    out_int (CODE_decrypted_message_media_video);
  } else if ((f->flags & FLAG_DOCUMENT_AUDIO)) {
    out_int (CODE_decrypted_message_media_audio);
  } else {
    out_int (CODE_decrypted_message_media_document);
  }
  if (f->flags == -1 || !(f->flags & FLAG_DOCUMENT_AUDIO)) {
    out_cstring ("", 0);
    out_int (90);
    out_int (90);
  }
  
  if (f->flags == -1) {
    out_int (f->w);
    out_int (f->h);
  } else if (f->flags & FLAG_DOCUMENT_VIDEO) {
    out_int (f->duration);
    out_string (tg_mime_by_filename (f->file_name));
    out_int (f->w);
    out_int (f->h);
  } else if (f->flags & FLAG_DOCUMENT_AUDIO) {
    out_int (f->duration);
    out_string (tg_mime_by_filename (f->file_name));
  } else {
    out_string ("");
    out_string (tg_mime_by_filename (f->file_name));
    // document
  }
  
  out_int (f->size);
  out_cstring ((void *)f->key, 32);
  out_cstring ((void *)f->init_iv, 32);

  bl_do_create_message_media_encr_pending (TLS, r, TLS->our_id, tgl_get_peer_type (f->to_id), tgl_get_peer_id (f->to_id), time (0), 0, 0, save_ptr, packet_ptr - save_ptr);

  encr_finish (&P->encr_chat);
  if (f->size < (16 << 20)) {
    out_int (CODE_input_encrypted_file_uploaded);
  } else {
    out_int (CODE_input_encrypted_file_big_uploaded);
  }
  out_long (f->id);
  out_int (f->part_num);
  if (f->size < (16 << 20)) {
    out_string ("");
  }

  unsigned char md5[16];
  unsigned char str[64];
  memcpy (str, f->key, 32);
  memcpy (str + 32, f->init_iv, 32);
  MD5 (str, 64, md5);
  out_int ((*(int *)md5) ^ (*(int *)(md5 + 4)));

  tfree_secure (f->iv, 32);
  struct tgl_message *M = tgl_message_get (TLS, r);
  assert (M);
      
  tglq_send_query (TLS, TLS->DC_working, packet_ptr - packet_buffer, packet_buffer, &send_encr_file_methods, M, callback, callback_extra);
  
  tfree_str (f->file_name);
  tfree (f, sizeof (*f));
}

static void send_file_end (struct tgl_state *TLS, struct send_file *f, void *callback, void *callback_extra) {
  TLS->cur_uploaded_bytes -= f->size;
  TLS->cur_uploading_bytes -= f->size;
  clear_packet ();
    
  if (f->avatar) {
    send_avatar_end (TLS, f, callback, callback_extra);
    return;
  }
  if (!f->encr) {
    send_file_unencrypted_end (TLS, f, callback, callback_extra);
    return;
  }
  send_file_encrypted_end (TLS, f, callback, callback_extra);
  return;
}

static void send_part (struct tgl_state *TLS, struct send_file *f, void *callback, void *callback_extra) {
  if (f->fd >= 0) {
    if (!f->part_num) {
      TLS->cur_uploading_bytes += f->size;
    }
    clear_packet ();
    if (f->size < (16 << 20)) {
      out_int (CODE_upload_save_file_part);      
      out_long (f->id);
      out_int (f->part_num ++);
    } else {
      out_int (CODE_upload_save_big_file_part);      
      out_long (f->id);
      out_int (f->part_num ++);
      out_int ((f->size + f->part_size - 1) / f->part_size);
    }
    static char buf[512 << 10];
    int x = read (f->fd, buf, f->part_size);
    assert (x > 0);
    f->offset += x;
    TLS->cur_uploaded_bytes += x;
    
    if (f->encr) {
      if (x & 15) {
        assert (f->offset == f->size);
        tglt_secure_random (buf + x, (-x) & 15);
        x = (x + 15) & ~15;
      }
      
      AES_KEY aes_key;
      AES_set_encrypt_key (f->key, 256, &aes_key);
      AES_ige_encrypt ((void *)buf, (void *)buf, x, &aes_key, f->iv, 1);
      memset (&aes_key, 0, sizeof (aes_key));
    }
    out_cstring (buf, x);
    vlogprintf (E_DEBUG, "offset=%lld size=%lld\n", f->offset, f->size);
    if (f->offset == f->size) {
      close (f->fd);
      f->fd = -1;
    } else {
      assert (f->part_size == x);
    }
    //update_prompt ();
    tglq_send_query (TLS, TLS->DC_working, packet_ptr - packet_buffer, packet_buffer, &send_file_part_methods, f, callback, callback_extra);
  } else {
    send_file_end (TLS, f, callback, callback_extra);
  }
}

static void send_file_thumb (struct tgl_state *TLS, struct send_file *f, const void *thumb_data, int thumb_len, void *callback, void *callback_extra) {
  clear_packet ();
  f->thumb_id = lrand48 () * (1ll << 32) + lrand48 ();
  out_int (CODE_upload_save_file_part);
  out_long (f->thumb_id);
  out_int (0);
  out_cstring ((void *)thumb_data, thumb_len);
  tglq_send_query (TLS, TLS->DC_working, packet_ptr - packet_buffer, packet_buffer, &send_file_part_methods, f, callback, callback_extra);
}


static void _tgl_do_send_photo (struct tgl_state *TLS, int flags, tgl_peer_id_t to_id, const char *file_name, int avatar, int w, int h, int duration, const void *thumb_data, int thumb_len, void (*callback)(struct tgl_state *TLS, void *callback_extra, int success, struct tgl_message *M), void *callback_extra) {
  int fd = open (file_name, O_RDONLY);
  if (fd < 0) {
    vlogprintf (E_WARNING, "No such file '%s'\n", file_name);
    if (callback) {
      callback (TLS, callback_extra, 0, 0);
    }
    return;
  }
  struct stat buf;
  fstat (fd, &buf);
  long long size = buf.st_size;
  if (size <= 0) {
    vlogprintf (E_WARNING, "File has zero length\n");
    close (fd);
    if (callback) {
      callback (TLS, callback_extra, 0, 0);
    }
    return;
  }
  struct send_file *f = talloc0 (sizeof (*f));
  f->fd = fd;
  f->size = size;
  f->offset = 0;
  f->part_num = 0;
  f->avatar = avatar;
  int tmp = ((size + 2999) / 3000);
  f->part_size = (1 << 14);
  while (f->part_size < tmp) {
    f->part_size *= 2;
  }
  f->flags = flags;

  if (f->part_size > (512 << 10)) {
    close (fd);
    vlogprintf (E_WARNING, "Too big file. Maximal supported size is %d.\n", (512 << 10) * 1000);
    tfree (f, sizeof (*f));
    if (callback) {
      callback (TLS, callback_extra, 0, 0);
    }
    return;
  }
  
  tglt_secure_random (&f->id, 8);
  f->to_id = to_id;
  f->flags = flags;
  f->file_name = tstrdup (file_name);
  f->w = w;
  f->h = h;
  f->duration = duration;

  if (tgl_get_peer_type (f->to_id) == TGL_PEER_ENCR_CHAT) {
    f->encr = 1;
    f->iv = talloc (32);
    tglt_secure_random (f->iv, 32);
    f->init_iv = talloc (32);
    memcpy (f->init_iv, f->iv, 32);
    f->key = talloc (32);
    tglt_secure_random (f->key, 32);
  }
 
  if (!f->encr && f->flags != -1 && thumb_len > 0) {
    send_file_thumb (TLS, f, thumb_data, thumb_len, callback, callback_extra);
  } else {
    send_part (TLS, f, callback, callback_extra);
  }
}

void tgl_do_send_document_ex (struct tgl_state *TLS, int flags, tgl_peer_id_t to_id, const char *file_name, int w, int h, int duration, const void *thumb, int thumb_len, void (*callback)(struct tgl_state *TLS, void *callback_extra, int success, struct tgl_message *M), void *callback_extra) {
  _tgl_do_send_photo (TLS, flags, to_id, file_name, 0, w, h, duration, thumb, thumb_len, callback, callback_extra);
}

void tgl_do_send_document (struct tgl_state *TLS, int flags, tgl_peer_id_t to_id, const char *file_name, void (*callback)(struct tgl_state *TLS, void *callback_extra, int success, struct tgl_message *M), void *callback_extra) {
  if (flags == -2) {
    char *mime_type = tg_mime_by_filename (file_name);
    if (!memcmp (mime_type, "image/", 6)) {
      flags = -1;
    } else if (!memcmp (mime_type, "video/", 6)) {
      flags = FLAG_DOCUMENT_VIDEO;
    } else if (!memcmp (mime_type, "audio/", 6)) {
      flags = FLAG_DOCUMENT_AUDIO;
    } else {
      flags = 0;
    }
  }
  _tgl_do_send_photo (TLS, flags, to_id, file_name, 0, 100, 100, 100, 0, 0, callback, callback_extra);
}

void tgl_do_set_chat_photo (struct tgl_state *TLS, tgl_peer_id_t chat_id, const char *file_name, void (*callback)(struct tgl_state *TLS,void *callback_extra, int success, struct tgl_message *M), void *callback_extra) {
  assert (tgl_get_peer_type (chat_id) == TGL_PEER_CHAT);
  _tgl_do_send_photo (TLS, -1, chat_id, file_name, tgl_get_peer_id (chat_id), 0, 0, 0, 0, 0, callback, callback_extra);
}

void tgl_do_set_profile_photo (struct tgl_state *TLS, const char *file_name, void (*callback)(struct tgl_state *TLS, void *callback_extra, int success), void *callback_extra) {
  _tgl_do_send_photo (TLS, -1, TGL_MK_USER(TLS->our_id), file_name, -1, 0, 0, 0, 0, 0, (void *)callback, callback_extra);
}
/* }}} */

/* {{{ Profile name */

int set_profile_name_on_answer (struct tgl_state *TLS, struct query *q) {
  struct tgl_user *U = tglf_fetch_alloc_user (TLS);
  if (q->callback) {
    ((void (*)(struct tgl_state *, void *, int, struct tgl_user  *))q->callback) (TLS, q->callback_extra, 1, U);
  }
  return 0;
}

static struct query_methods set_profile_name_methods = {
  .on_answer = set_profile_name_on_answer,
  .on_error = q_ptr_on_error,
  .type = TYPE_TO_PARAM(user)
};

void tgl_do_set_profile_name (struct tgl_state *TLS, const char *first_name, const char *last_name, void (*callback)(struct tgl_state *TLS, void *callback_extra, int success, struct tgl_user *U), void *callback_extra) {
  clear_packet ();
  out_int (CODE_account_update_profile);
  out_string (first_name);
  out_string (last_name);

  tglq_send_query (TLS, TLS->DC_working, packet_ptr - packet_buffer, packet_buffer, &set_profile_name_methods, 0, callback, callback_extra);
}

void tgl_do_set_username (struct tgl_state *TLS, const char *name, void (*callback)(struct tgl_state *TLS, void *callback_extra, int success, struct tgl_user *U), void *callback_extra) {
  clear_packet ();
  out_int (CODE_account_update_username);
  out_string (name);

  tglq_send_query (TLS, TLS->DC_working, packet_ptr - packet_buffer, packet_buffer, &set_profile_name_methods, 0, callback, callback_extra);
}
/* }}} */

/* {{{ Contacts search */

int contact_search_on_answer (struct tgl_state *TLS, struct query *q) {
  assert (fetch_int () == CODE_contacts_found);
  assert (fetch_int () == CODE_vector);
  int n = fetch_int ();
  int i;
  for (i = 0; i < n; i++) {
    assert (fetch_int () == (int)CODE_contact_found);
    fetch_int ();
  }
  assert (fetch_int () == CODE_vector);
  n = fetch_int ();

  struct tgl_user **UL = talloc (sizeof (void *) * n);
  for (i = 0; i < n; i++) {
    UL[i] = tglf_fetch_alloc_user (TLS);
  }

  if (q->callback) {
    ((void (*)(struct tgl_state *,void *, int, int, struct tgl_user  **))q->callback) (TLS, q->callback_extra, 1, n, UL);
  }
  tfree (UL, sizeof (void *) * n);
  return 0;
}

static struct query_methods contact_search_methods = {
  .on_answer = contact_search_on_answer,
  .on_error = q_list_on_error,
  .type = TYPE_TO_PARAM(contacts_found)
};

void tgl_do_contact_search (struct tgl_state *TLS, const char *name, int limit, void (*callback)(struct tgl_state *TLS, void *callback_extra, int success, int cnt, struct tgl_user *U[]), void *callback_extra) {
  clear_packet ();
  out_int (CODE_contacts_search);
  out_string (name);
  out_int (limit);

  tglq_send_query (TLS, TLS->DC_working, packet_ptr - packet_buffer, packet_buffer, &contact_search_methods, 0, callback, callback_extra);
}
/* }}} */

/* {{{ Forward */
static int fwd_msg_on_answer (struct tgl_state *TLS, struct query *q) {
  assert (fetch_int () == (int)CODE_messages_stated_message);
  struct tgl_message *M = tglf_fetch_alloc_message (TLS);
  assert (fetch_int () == CODE_vector);
  int n, i;
  n = fetch_int ();
  for (i = 0; i < n; i++) {
    tglf_fetch_alloc_chat (TLS);
  }
  assert (fetch_int () == CODE_vector);
  n = fetch_int ();
  for (i = 0; i < n; i++) {
    tglf_fetch_alloc_user (TLS);
  }
  //tglu_fetch_pts ();
  int pts = fetch_int ();
  
  bl_do_msg_set_outbound (TLS, M->id);
  int seq = fetch_int ();
  if (seq == TLS->seq + 1 && !(TLS->locks & TGL_LOCK_DIFF)) {
    bl_do_set_pts (TLS, pts);
    bl_do_msg_seq_update (TLS, M->id);
  } else {
    if (seq > TLS->seq + 1) {
      vlogprintf (E_NOTICE, "Hole in seq\n");
      tgl_do_get_difference (TLS, 0, 0, 0);
    }
  }
  //print_message (M);
  if (q->callback) {
    ((void (*)(struct tgl_state *, void *, int, struct tgl_message *))q->callback) (TLS, q->callback_extra, 1, M);
  }
  return 0;
}

static struct query_methods fwd_msg_methods = {
  .on_answer = fwd_msg_on_answer,
  .on_error = q_ptr_on_error,
  .type = TYPE_TO_PARAM(messages_stated_message)
};

void tgl_do_forward_message (struct tgl_state *TLS, tgl_peer_id_t id, int n, void (*callback)(struct tgl_state *TLS, void *callback_extra, int success, struct tgl_message *M), void *callback_extra) {
  if (tgl_get_peer_type (id) == TGL_PEER_ENCR_CHAT) {
    vlogprintf (E_WARNING, "Can not forward messages from secret chat\n");
    if (callback) {
      callback (TLS, callback_extra, 0, 0);
    }
    return;
  }
  clear_packet ();
  out_int (CODE_messages_forward_message);
  out_peer_id (TLS, id);
  out_int (n);
  long long r;
  tglt_secure_random (&r, 8);
  out_long (r);
  tglq_send_query (TLS, TLS->DC_working, packet_ptr - packet_buffer, packet_buffer, &fwd_msg_methods, 0, callback, callback_extra);
}

void tgl_do_send_contact (struct tgl_state *TLS, tgl_peer_id_t id, const char *phone, int phone_len, const char *first_name, int first_name_len, const char *last_name, int last_name_len, void (*callback)(struct tgl_state *TLS, void *callback_extra, int success, struct tgl_message *M), void *callback_extra) {
  if (tgl_get_peer_type (id) == TGL_PEER_ENCR_CHAT) {
    if (callback) {
      callback (TLS, callback_extra, 0, 0);
    }
    return;
  }
  long long t;
  tglt_secure_random (&t, 8);
  vlogprintf (E_DEBUG, "t = %lld\n", t);

  clear_packet ();
  out_int (CODE_messages_send_media);
  out_peer_id (TLS, id);
  out_int (CODE_input_media_contact);
  out_cstring (phone, phone_len);
  out_cstring (first_name, first_name_len);
  out_cstring (last_name, last_name_len);
  out_long (t);

  tglq_send_query (TLS, TLS->DC_working, packet_ptr - packet_buffer, packet_buffer, &fwd_msg_methods, 0, callback, callback_extra);
}

void tgl_do_forward_media (struct tgl_state *TLS, tgl_peer_id_t id, int n, void (*callback)(struct tgl_state *TLS, void *callback_extra, int success, struct tgl_message *M), void *callback_extra) {
  if (tgl_get_peer_type (id) == TGL_PEER_ENCR_CHAT) {
    vlogprintf (E_WARNING, "Can not forward messages from secret chat\n");
    if (callback) {
      callback (TLS, callback_extra, 0, 0);
    }
    return;
  }
  struct tgl_message *M = tgl_message_get (TLS, n);
  if (!M) {
    vlogprintf (E_WARNING, "No such message\n");
    if (callback) {
      callback (TLS, callback_extra, 0, 0);
    }
    return;
  }
  if (M->flags & FLAG_ENCRYPTED) {
    vlogprintf (E_WARNING, "Can not forward media from encrypted message\n");
    if (callback) {
      callback (TLS, callback_extra, 0, 0);
    }
    return;
  }
  if (M->media.type != tgl_message_media_photo && M->media.type != tgl_message_media_document) {
    vlogprintf (E_WARNING, "Can only forward photo/document\n");
    if (callback) {
      callback (TLS, callback_extra, 0, 0);
    }
    return;
  }
  clear_packet ();
  out_int (CODE_messages_send_media);
  out_peer_id (TLS, id);
  switch (M->media.type) {
  case tgl_message_media_photo:
    out_int (CODE_input_media_photo);
    out_int (CODE_input_photo);
    out_long (M->media.photo.id);
    out_long (M->media.photo.access_hash);
    break;
  case tgl_message_media_document:
    out_int (CODE_input_media_document);
    out_int (CODE_input_document);
    out_long (M->media.document.id);
    out_long (M->media.document.access_hash);
    break;
  default:
    assert (0);
  }
  long long r;
  tglt_secure_random (&r, 8);
  out_long (r);

  tglq_send_query (TLS, TLS->DC_working, packet_ptr - packet_buffer, packet_buffer, &fwd_msg_methods, 0, callback, callback_extra);
}
/* }}} */

/* {{{ Send location */

void tgl_do_send_location(struct tgl_state *TLS, tgl_peer_id_t id, double latitude, double longitude, void (*callback)(struct tgl_state *TLS, void *callback_extra, int success, struct tgl_message *M), void *callback_extra) {
  if (tgl_get_peer_type (id) == TGL_PEER_ENCR_CHAT) {
    clear_packet ();
    out_int (CODE_messages_send_encrypted);
    out_int (CODE_input_encrypted_chat);
    out_int (tgl_get_peer_id (id));
    tgl_peer_t *P = tgl_peer_get (TLS, id);
    assert (P);
    out_long (P->encr_chat.access_hash);

    long long r;
    tglt_secure_random (&r, 8);
    out_long (r);
    encr_start ();
    if (P->encr_chat.layer <= 16) {
      out_int (CODE_decrypted_message_l16);
    } else {
      out_int (CODE_decrypted_message_layer);
      out_random (15 + 4 * (lrand48 () % 3));
      out_int (TGL_ENCRYPTED_LAYER);
      out_int (2 * P->encr_chat.in_seq_no + (P->encr_chat.admin_id != TLS->our_id));
      out_int (2 * P->encr_chat.out_seq_no + (P->encr_chat.admin_id == TLS->our_id));
      out_int (CODE_decrypted_message);
    }
    out_long (r);
    if (P->encr_chat.layer < 17) {
      out_random (15 + 4 * (lrand48 () % 3));
    } else {
      out_int (P->encr_chat.ttl);
    }
    out_string ("");
    int *save_ptr = packet_ptr;
    out_int (CODE_decrypted_message_media_geo_point);
    out_double (latitude);
    out_double (longitude);

    bl_do_create_message_media_encr_pending (TLS, r, TLS->our_id, tgl_get_peer_type (id), tgl_get_peer_id (id), time (0), 0, 0, save_ptr, packet_ptr - save_ptr);

    encr_finish (&P->encr_chat);
      
    struct tgl_message *M = tgl_message_get (TLS, r);
    assert (M);
    
    tglq_send_query (TLS, TLS->DC_working, packet_ptr - packet_buffer, packet_buffer, &msg_send_encr_methods, M, callback, callback_extra);
  } else {
    long long t;
    tglt_secure_random (&t, 8);
    vlogprintf (E_DEBUG, "t = %lld\n", t);

    clear_packet ();
    out_int (CODE_messages_send_media);
    out_peer_id (TLS, id);
    out_int (CODE_input_media_geo_point);
    out_int (CODE_input_geo_point);
    out_double (latitude);
    out_double (longitude);
    out_long (t);

    tglq_send_query (TLS, TLS->DC_working, packet_ptr - packet_buffer, packet_buffer, &fwd_msg_methods, 0, callback, callback_extra);
  }
}
/* }}} */

/* {{{ Rename chat */
static int rename_chat_on_answer (struct tgl_state *TLS, struct query *q) {
  assert (fetch_int () == (int)CODE_messages_stated_message);
  struct tgl_message *M = tglf_fetch_alloc_message (TLS);
  assert (fetch_int () == CODE_vector);
  int n, i;
  n = fetch_int ();
  for (i = 0; i < n; i++) {
    tglf_fetch_alloc_chat (TLS);
  }
  assert (fetch_int () == CODE_vector);
  n = fetch_int ();
  for (i = 0; i < n; i++) {
    tglf_fetch_alloc_user (TLS);
  }
  //tglu_fetch_pts ();
  int pts = fetch_int ();

  int seq = fetch_int ();
  if (seq == TLS->seq + 1 && !(TLS->locks & TGL_LOCK_DIFF)) {
    bl_do_set_pts (TLS, pts);
    bl_do_msg_seq_update (TLS, M->id);
  } else {
    if (seq > TLS->seq + 1) {
      vlogprintf (E_NOTICE, "Hole in seq\n");
      tgl_do_get_difference (TLS, 0, 0, 0);
    }
  }
  //print_message (M);
  if (q->callback) {
    ((void (*)(struct tgl_state *, void *, int, struct tgl_message *))q->callback) (TLS, q->callback_extra, 1, M);
  }
  return 0;
}

static struct query_methods rename_chat_methods = {
  .on_answer = rename_chat_on_answer,
  .on_error = q_ptr_on_error,
  .type = TYPE_TO_PARAM(messages_stated_message)
};

void tgl_do_rename_chat (struct tgl_state *TLS, tgl_peer_id_t id, const char *name, void (*callback)(struct tgl_state *TLS, void *callback_extra, int success, struct tgl_message *M), void *callback_extra) {
  clear_packet ();
  out_int (CODE_messages_edit_chat_title);
  assert (tgl_get_peer_type (id) == TGL_PEER_CHAT);
  out_int (tgl_get_peer_id (id));
  out_string (name);
  tglq_send_query (TLS, TLS->DC_working, packet_ptr - packet_buffer, packet_buffer, &rename_chat_methods, 0, callback, callback_extra);
}
/* }}} */

/* {{{ Chat info */

static int chat_info_on_answer (struct tgl_state *TLS, struct query *q) {
  struct tgl_chat *C = tglf_fetch_alloc_chat_full (TLS);
  //print_chat_info (C);
  if (q->callback) {
    ((void (*)(struct tgl_state *, void *, int, struct tgl_chat *))q->callback) (TLS, q->callback_extra, 1, C);
  }
  return 0;
}

static struct query_methods chat_info_methods = {
  .on_answer = chat_info_on_answer,
  .on_error = q_ptr_on_error,
  .type = TYPE_TO_PARAM(messages_chat_full)
};

void tgl_do_get_chat_info (struct tgl_state *TLS, tgl_peer_id_t id, int offline_mode, void (*callback)(struct tgl_state *TLS, void *callback_extra, int success, struct tgl_chat *C), void *callback_extra) {
  if (offline_mode) {
    tgl_peer_t *C = tgl_peer_get (TLS, id);
    if (!C) {
      vlogprintf (E_WARNING, "No such chat\n");
      if (callback) {
        callback (TLS, callback_extra, 0, 0);
      }
    } else {
      //print_chat_info (&C->chat);
      if (callback) {
        callback (TLS, callback_extra, 1, &C->chat);
      }
    }
    return;
  }
  clear_packet ();
  out_int (CODE_messages_get_full_chat);
  assert (tgl_get_peer_type (id) == TGL_PEER_CHAT);
  out_int (tgl_get_peer_id (id));
  tglq_send_query (TLS, TLS->DC_working, packet_ptr - packet_buffer, packet_buffer, &chat_info_methods, 0, callback, callback_extra);
}
/* }}} */

/* {{{ User info */

/*void print_user_info (struct tgl_user *U) {
  tgl_peer_t *C = (void *)U;
  print_start ();
  push_color (COLOR_YELLOW);
  printf ("User ");
  print_user_name (U->id, C);
  printf (":\n");
  printf ("\treal name: %s %s\n", U->real_first_name, U->real_last_name);
  printf ("\tphone: %s\n", U->phone);
  if (U->status.online > 0) {
    printf ("\tonline\n");
  } else {
    printf ("\toffline (was online ");
    print_date_full (U->status.when);
    printf (")\n");
  }
  pop_color ();
  print_end ();
}*/

static int user_info_on_answer (struct tgl_state *TLS, struct query *q) {
  struct tgl_user *U = tglf_fetch_alloc_user_full (TLS);
  if (q->callback) {
    ((void (*)(struct tgl_state *, void *, int, struct tgl_user *))q->callback) (TLS, q->callback_extra, 1, U);
  }
  return 0;
}

static struct query_methods user_info_methods = {
  .on_answer = user_info_on_answer,
  .on_error = q_ptr_on_error,
  .type = TYPE_TO_PARAM(user_full)
};

void tgl_do_get_user_info (struct tgl_state *TLS, tgl_peer_id_t id, int offline_mode, void (*callback)(struct tgl_state *TLS, void *callback_extra, int success, struct tgl_user *U), void *callback_extra) {
  if (offline_mode) {
    tgl_peer_t *C = tgl_peer_get (TLS, id);
    if (!C) {
      vlogprintf (E_WARNING, "No such user\n");
      if (callback) {
        callback (TLS, callback_extra, 0, 0);
      }
    } else {
      if (callback) {
        callback (TLS, callback_extra, 1, &C->user);
      }
    }
    return;
  }
  clear_packet ();
  out_int (CODE_users_get_full_user);
  assert (tgl_get_peer_type (id) == TGL_PEER_USER);
  tgl_peer_t *U = tgl_peer_get (TLS, id);
  if (U && U->user.access_hash) {
    out_int (CODE_input_user_foreign);
    out_int (tgl_get_peer_id (id));
    out_long (U->user.access_hash);
  } else {
    out_int (CODE_input_user_contact);
    out_int (tgl_get_peer_id (id));
  }
  tglq_send_query (TLS, TLS->DC_working, packet_ptr - packet_buffer, packet_buffer, &user_info_methods, 0, callback, callback_extra);
}
/* }}} */

/* {{{ Load photo/video */
struct download {
  int offset;
  int size;
  long long volume;
  long long secret;
  long long access_hash;
  int local_id;
  int dc;
  int next;
  int fd;
  char *name;
  char *ext;
  long long id;
  unsigned char *iv;
  unsigned char *key;
  int type;
  int refcnt;
};


static void end_load (struct tgl_state *TLS, struct download *D, void *callback, void *callback_extra) {
  TLS->cur_downloading_bytes -= D->size;
  TLS->cur_downloaded_bytes -= D->size;
  //update_prompt ();
  close (D->fd);
  /*if (D->next == 1) {
    logprintf ("Done: %s\n", D->name);
  } else if (D->next == 2) {
    static char buf[PATH_MAX];
    if (tsnprintf (buf, sizeof (buf), OPEN_BIN, D->name) >= (int) sizeof (buf)) {
      logprintf ("Open image command buffer overflow\n");
    } else {
      int x = system (buf);
      if (x < 0) {
        logprintf ("Can not open image viewer: %m\n");
        logprintf ("Image is at %s\n", D->name);
      }
    }
  }*/

  if (callback) {
    ((void (*)(struct tgl_state *, void *, int, char *))callback) (TLS, callback_extra, 1, D->name);
  }

  if (D->iv) {
    tfree_secure (D->iv, 32);
  }
  tfree_str (D->name);
  tfree (D, sizeof (*D));
}

static void load_next_part (struct tgl_state *TLS, struct download *D, void *callback, void *callback_extra);
static int download_on_answer (struct tgl_state *TLS, struct query *q) {
  assert (fetch_int () == (int)CODE_upload_file);
  unsigned x = fetch_int ();
  assert (x);
  struct download *D = q->extra;
  if (D->fd == -1) {
    D->fd = open (D->name, O_CREAT | O_WRONLY, 0640);
    if (D->fd < 0) {
      vlogprintf (E_ERROR, "Can not open for writing: %m\n");
      assert (D->fd >= 0);
    }
  }
  fetch_int (); // mtime
  int len = prefetch_strlen ();
  assert (len >= 0);
  TLS->cur_downloaded_bytes += len;
  //update_prompt ();
  if (D->iv) {
    unsigned char *ptr = (void *)fetch_str (len);
    assert (!(len & 15));
    AES_KEY aes_key;
    AES_set_decrypt_key (D->key, 256, &aes_key);
    AES_ige_encrypt (ptr, ptr, len, &aes_key, D->iv, 0);
    memset (&aes_key, 0, sizeof (aes_key));
    if (len > D->size - D->offset) {
      len = D->size - D->offset;
    }
    assert (write (D->fd, ptr, len) == len);
  } else {
    assert (write (D->fd, fetch_str (len), len) == len);
  }
  D->offset += len;
  D->refcnt --;
  if (D->offset < D->size) {
    load_next_part (TLS, D, q->callback, q->callback_extra);
    return 0;
  } else {
    if (!D->refcnt) {
      end_load (TLS, D, q->callback, q->callback_extra);
    }
    return 0;
  }
}

static int download_on_error (struct tgl_state *TLS, struct query *q, int error_code, int error_len, const char *error) {
  struct download *D = q->extra;
  if (D->fd >= 0) {
    close (D->fd);
  }
  
  if (q->callback) {
    ((void (*)(struct tgl_state *, void *, int, char *))q->callback) (TLS, q->callback_extra, 0, NULL);
  }

  if (D->iv) {
    tfree_secure (D->iv, 32);
  }
  tfree_str (D->name);
  if (D->ext) {
    tfree_str (D->ext);
  }
  tfree (D, sizeof (*D));
  return 0;
}

static struct query_methods download_methods = {
  .on_answer = download_on_answer,
  .on_error = download_on_error,
  .type = TYPE_TO_PARAM(upload_file)
};

static void load_next_part (struct tgl_state *TLS, struct download *D, void *callback, void *callback_extra) {
  if (!D->offset) {
    static char buf[PATH_MAX];
    int l;
    if (!D->id) {
      l = tsnprintf (buf, sizeof (buf), "%s/download_%lld_%d.jpg", TLS->downloads_directory, D->volume, D->local_id);
    } else {
      if (D->ext) {
        l = tsnprintf (buf, sizeof (buf), "%s/download_%lld.%s", TLS->downloads_directory, D->id, D->ext);
      } else {
        l = tsnprintf (buf, sizeof (buf), "%s/download_%lld", TLS->downloads_directory, D->id);
      }
    }
    if (l >= (int) sizeof (buf)) {
      vlogprintf (E_ERROR, "Download filename is too long");
      exit (1);
    }
    D->name = tstrdup (buf);
    struct stat st;
    if (stat (buf, &st) >= 0) {
      D->offset = st.st_size;      
      if (D->offset >= D->size) {
        TLS->cur_downloading_bytes += D->size;
        TLS->cur_downloaded_bytes += D->offset;
        vlogprintf (E_NOTICE, "Already downloaded\n");
        end_load (TLS, D, callback, callback_extra);        
        return;
      }
    }
    
    TLS->cur_downloading_bytes += D->size;
    TLS->cur_downloaded_bytes += D->offset;
    //update_prompt ();
  }
  D->refcnt ++;
  clear_packet ();
  out_int (CODE_upload_get_file);
  if (!D->id) {
    out_int (CODE_input_file_location);
    out_long (D->volume);
    out_int (D->local_id);
    out_long (D->secret);
  } else {
    if (D->iv) {
      out_int (CODE_input_encrypted_file_location);
    } else {
      out_int (D->type);
    }
    out_long (D->id);
    out_long (D->access_hash);
  }
  out_int (D->offset);
  out_int (1 << 14);
  tglq_send_query (TLS, TLS->DC_list[D->dc], packet_ptr - packet_buffer, packet_buffer, &download_methods, D, callback, callback_extra);
  //tglq_send_query (TLS, TLS->DC_working, packet_ptr - packet_buffer, packet_buffer, &download_methods, D);
}

void tgl_do_load_photo_size (struct tgl_state *TLS, struct tgl_photo_size *P, void (*callback)(struct tgl_state *TLS, void *callback_extra, int success, const char *filename), void *callback_extra) {
  if (!P->loc.dc) {
    vlogprintf (E_WARNING, "Bad video thumb\n");
    if (callback) {
      callback (TLS, callback_extra, 0, 0);
    }
    return;
  }
  
  assert (P);
  struct download *D = talloc0 (sizeof (*D));
  D->id = 0;
  D->offset = 0;
  D->size = P->size;
  D->volume = P->loc.volume;
  D->dc = P->loc.dc;
  D->local_id = P->loc.local_id;
  D->secret = P->loc.secret;
  D->name = 0;
  D->fd = -1;
  load_next_part (TLS, D, callback, callback_extra);
}

void tgl_do_load_photo (struct tgl_state *TLS, struct tgl_photo *photo, void (*callback)(struct tgl_state *TLS, void *callback_extra, int success, const char *filename), void *callback_extra) {
  if (!photo->sizes_num) { 
    vlogprintf (E_WARNING, "No sizes\n");
    if (callback) {
      callback (TLS, callback_extra, 0, 0);
    }
    return; 
  }
  int max = -1;
  int maxi = 0;
  int i;
  for (i = 0; i < photo->sizes_num; i++) {
    if (photo->sizes[i].w + photo->sizes[i].h > max) {
      max = photo->sizes[i].w + photo->sizes[i].h;
      maxi = i;
    }
  }
  tgl_do_load_photo_size (TLS, &photo->sizes[maxi], callback, callback_extra);
}

void tgl_do_load_document_thumb (struct tgl_state *TLS, struct tgl_document *video, void (*callback)(struct tgl_state *TLS, void *callback_extra, int success, const char *filename), void *callback_extra) {
  tgl_do_load_photo_size (TLS, &video->thumb, callback, callback_extra);
}

void tgl_do_load_document (struct tgl_state *TLS, struct tgl_document *V, void (*callback)(struct tgl_state *TLS, void *callback_extra, int success, const char *filename), void *callback_extra) {
  assert (V);
  struct download *D = talloc0 (sizeof (*D));
  D->offset = 0;
  D->size = V->size;
  D->id = V->id;
  D->access_hash = V->access_hash;
  D->dc = V->dc_id;
  D->name = 0;
  D->fd = -1;
  D->type = CODE_input_document_file_location;
  if (V->mime_type) {
    char *r = tg_extension_by_mime (V->mime_type);
    if (r) {
      D->ext = tstrdup (r);
    }
  }
  load_next_part (TLS, D, callback, callback_extra);
}

void tgl_do_load_encr_document (struct tgl_state *TLS, struct tgl_encr_document *V, void (*callback)(struct tgl_state *TLS, void *callback_extra, int success, const char *filename), void *callback_extra) {
  assert (V);
  struct download *D = talloc0 (sizeof (*D));
  D->offset = 0;
  D->size = V->size;
  D->id = V->id;
  D->access_hash = V->access_hash;
  D->dc = V->dc_id;
  D->name = 0;
  D->fd = -1;
  D->key = V->key;
  D->iv = talloc (32);
  memcpy (D->iv, V->iv, 32);
  if (V->mime_type) {
    char *r = tg_extension_by_mime (V->mime_type);
    if (r) {
      D->ext = tstrdup (r);
    }
  }
  load_next_part (TLS, D, callback, callback_extra);
      
  unsigned char md5[16];
  unsigned char str[64];
  memcpy (str, V->key, 32);
  memcpy (str + 32, V->iv, 32);
  MD5 (str, 64, md5);
  assert (V->key_fingerprint == ((*(int *)md5) ^ (*(int *)(md5 + 4))));
}
/* }}} */

/* {{{ Export auth */

static int import_auth_on_answer (struct tgl_state *TLS, struct query *q) {
  assert (fetch_int () == (int)CODE_auth_authorization);
  fetch_int (); // expires
  tglf_fetch_alloc_user (TLS);
  
  bl_do_dc_signed (TLS, ((struct tgl_dc *)q->extra)->id);

  if (q->callback) {
    ((void (*)(struct tgl_state *, void *, int))q->callback) (TLS, q->callback_extra, 1);
  }
  return 0;
}

static struct query_methods import_auth_methods = {
  .on_answer = import_auth_on_answer,
  .on_error = fail_on_error,
  .type = TYPE_TO_PARAM(auth_authorization)
};

static int export_auth_on_answer (struct tgl_state *TLS, struct query *q) { 
  assert (fetch_int () == (int)CODE_auth_exported_authorization);
  bl_do_set_our_id (TLS, fetch_int ());
  int l = prefetch_strlen ();
  char *s = talloc (l);
  memcpy (s, fetch_str (l), l);
 
  //struct tgl_dc *DC = q->extra;
  //vlogprintf (0, "exported auth (to %d)\n", DC->id);

  clear_packet ();
  tgl_do_insert_header (TLS);
  out_int (CODE_auth_import_authorization);
  out_int (TLS->our_id);
  out_cstring (s, l);
  tglq_send_query (TLS, q->extra, packet_ptr - packet_buffer, packet_buffer, &import_auth_methods, q->extra, q->callback, q->callback_extra);
  tfree (s, l);
  return 0;
}

static struct query_methods export_auth_methods = {
  .on_answer = export_auth_on_answer,
  .on_error = fail_on_error,
  .type = TYPE_TO_PARAM(auth_exported_authorization)
};

void tgl_do_export_auth (struct tgl_state *TLS, int num, void (*callback) (struct tgl_state *TLS, void *callback_extra, int success), void *callback_extra) {
  clear_packet ();
  out_int (CODE_auth_export_authorization);
  out_int (num);
  tglq_send_query (TLS, TLS->DC_working, packet_ptr - packet_buffer, packet_buffer, &export_auth_methods, TLS->DC_list[num], callback, callback_extra);
}
/* }}} */

/* {{{ Add contact */
static int add_contact_on_answer (struct tgl_state *TLS, struct query *q) {
  assert (fetch_int () == (int)CODE_contacts_imported_contacts);
  assert (fetch_int () == CODE_vector);
  int n = fetch_int ();
  if (n > 0) {
    vlogprintf (E_DEBUG, "Added successfully");
  } else {
    vlogprintf (E_DEBUG, "Not added");
  }
  int i;
  for (i = 0; i < n ; i++) {
    assert (fetch_int () == (int)CODE_imported_contact);
    fetch_int (); // uid
    fetch_long (); // client_id
  }
  assert (fetch_int () == CODE_vector);
  n = fetch_int ();
  for (i = 0; i < n; i++) {
    long long id = fetch_long ();
    vlogprintf (E_NOTICE, "contact #%lld not added. Please retry\n", id);
  }
  assert (fetch_int () == CODE_vector);
  n = fetch_int ();

  struct tgl_user **UL = talloc (n * sizeof (void *));
  for (i = 0; i < n; i++) {
    UL[i] = tglf_fetch_alloc_user (TLS);
  }

  if (q->callback) {
    ((void (*)(struct tgl_state *, void *, int, int, struct tgl_user **))q->callback) (TLS, q->callback_extra, 1, n, UL);
  }
  tfree (UL, n * sizeof (void *));
  return 0;
}

static struct query_methods add_contact_methods = {
  .on_answer = add_contact_on_answer,
  .on_error = q_list_on_error,
  .type = TYPE_TO_PARAM(contacts_imported_contacts)
};

void tgl_do_add_contact (struct tgl_state *TLS, const char *phone, int phone_len, const char *first_name, int first_name_len, const char *last_name, int last_name_len, int force, void (*callback)(struct tgl_state *TLS,void *callback_extra, int success, int size, struct tgl_user *users[]), void *callback_extra) {
  clear_packet ();
  out_int (CODE_contacts_import_contacts);
  out_int (CODE_vector);
  out_int (1);
  out_int (CODE_input_phone_contact);
  long long r;
  tglt_secure_random (&r, 8);
  out_long (r);
  out_cstring (phone, phone_len);
  out_cstring (first_name, first_name_len);
  out_cstring (last_name, last_name_len);
  out_int (force ? CODE_bool_true : CODE_bool_false);
  tglq_send_query (TLS, TLS->DC_working, packet_ptr - packet_buffer, packet_buffer, &add_contact_methods, 0, callback, callback_extra);
}
/* }}} */

/* {{{ Add contact */
static int del_contact_on_answer (struct tgl_state *TLS, struct query *q) {
  assert (skip_type_contacts_link (TYPE_TO_PARAM(contacts_link)) >= 0);

  if (q->callback) {
    ((void (*)(struct tgl_state *, void *, int))q->callback) (TLS, q->callback_extra, 1);
  }
  return 0;
}

static struct query_methods del_contact_methods = {
  .on_answer = del_contact_on_answer,
  .on_error = q_void_on_error,
  .type = TYPE_TO_PARAM(contacts_link)
};

void tgl_do_del_contact (struct tgl_state *TLS, tgl_peer_id_t id, void (*callback)(struct tgl_state *TLS, void *callback_extra, int success), void *callback_extra) {
  if (tgl_get_peer_type (id) != TGL_PEER_USER) {
    if (callback) {
      callback (TLS, callback_extra, 0);
    }
    return;
  }
  clear_packet ();
  out_int (CODE_contacts_delete_contact);
  
  tgl_peer_t *U = tgl_peer_get (TLS, id);
  if (U && U->user.access_hash) {
    out_int (CODE_input_user_foreign);
    out_int (tgl_get_peer_id (id));
    out_long (U->user.access_hash);
  } else {
    out_int (CODE_input_user_contact);
    out_int (tgl_get_peer_id (id));
  }
  tglq_send_query (TLS, TLS->DC_working, packet_ptr - packet_buffer, packet_buffer, &del_contact_methods, 0, callback, callback_extra);
}
 /* }}} */

/* {{{ Msg search */
void _tgl_do_msg_search (struct tgl_state *TLS, tgl_peer_id_t id, int from, int to, int limit, int offset, int max_id, char *s, int list_offset, int list_size, struct tgl_message **list, void (*callback)(struct tgl_state *TLS,void *callback_extra, int success, int size, struct tgl_message *list[]), void *callback_extra);
static int msg_search_on_answer (struct tgl_state *TLS, struct query *q) {
  int count = -1;
  int i;
  int x = fetch_int ();
  assert (x == (int)CODE_messages_messages_slice || x == (int)CODE_messages_messages);
  if (x == (int)CODE_messages_messages_slice) {
    count = fetch_int ();
    //fetch_int ();
  }
  assert (fetch_int () == CODE_vector);
  void **T = q->extra;
  struct tgl_message **ML = T[0];
  int list_offset = (long)T[1];
  int list_size = (long)T[2];
  tgl_peer_id_t id = tgl_set_peer_id ((long)T[4], (long)T[3]);
  int limit = (long)T[5];
  int offset = (long)T[6];
  int from = (long)T[7];
  int to = (long)T[8];
  char *s = T[9];
  tfree (T, sizeof (void *) * 10);
  
  int n = fetch_int ();

  if (list_size - list_offset < n) {
    int new_list_size = 2 * list_size;
    if (new_list_size - list_offset < n) {
      new_list_size = n + list_offset;
    }
    ML = trealloc (ML, list_size * sizeof (void *), new_list_size * sizeof (void *));
    assert (ML);
    list_size = new_list_size;
  }
  //struct tgl_message **ML = talloc (sizeof (void *) * n);
  for (i = 0; i < n; i++) {
    ML[i + list_offset] = tglf_fetch_alloc_message (TLS);
  }
  list_offset += n;
  offset += n;
  limit -= n;
  if (count >= 0 && limit + offset >= count) {
    limit = count - offset;
    if (limit < 0) { limit = 0; }
  }
  assert (limit >= 0);
  
  assert (fetch_int () == CODE_vector);
  n = fetch_int ();
  for (i = 0; i < n; i++) {
    tglf_fetch_alloc_chat (TLS);
  }
  assert (fetch_int () == CODE_vector);
  n = fetch_int ();
  for (i = 0; i < n; i++) {
    tglf_fetch_alloc_user (TLS);
  }

 
  if (limit <= 0 || x == (int)CODE_messages_messages) {
    if (q->callback) {
      ((void (*)(struct tgl_state *, void *, int, int, struct tgl_message **))q->callback) (TLS, q->callback_extra, 1, list_offset, ML);
    }
  
    tfree_str (s);
    tfree (ML, sizeof (void *) * list_size);
  } else {
   _tgl_do_msg_search (TLS, id, from, to, limit, 0, ML[list_offset - 1]->id, s, list_offset, list_size, ML, q->callback, q->callback_extra);
  }
  return 0;
}

static int msg_search_on_error (struct tgl_state *TLS, struct query *q, int error_code, int error_len, const char *error) {
  void **T = q->extra;
  struct tgl_message **ML = T[0];
  int list_size = (long)T[2];
  char *s = T[9];
  tfree (T, sizeof (void *) * 10);
  tfree_str (s);
  tfree (ML, sizeof (void *) * list_size);
  if (q->callback) {
    ((void (*)(struct tgl_state *, void *, int, int, struct tgl_message **))q->callback) (TLS, q->callback_extra, 0, 0, NULL);
  }
  return 0;
}

static struct query_methods msg_search_methods = {
  .on_answer = msg_search_on_answer,
  .on_error = msg_search_on_error,
  .type = TYPE_TO_PARAM(messages_messages)
};

void _tgl_do_msg_search (struct tgl_state *TLS, tgl_peer_id_t id, int from, int to, int limit, int offset, int max_id, char *s, int list_offset, int list_size, struct tgl_message **list, void (*callback)(struct tgl_state *TLS, void *callback_extra, int success, int size, struct tgl_message *list[]), void *callback_extra) {
  if (tgl_get_peer_type (id) == TGL_PEER_ENCR_CHAT) {
    vlogprintf (E_WARNING, "Can not search in secure chat\n");
    if (callback) {
      callback (TLS, callback_extra, 0, 0, 0);
    }
    return;
  }
  clear_packet ();
  out_int (CODE_messages_search);
  if (tgl_get_peer_type (id) == TGL_PEER_UNKNOWN) {
    out_int (CODE_input_peer_empty);
  } else {
    out_peer_id (TLS, id);
  }
  void **T = talloc (sizeof (void *) * 10);
  T[0] = list;
  T[1] = (void *)(long)list_offset;
  T[2] = (void *)(long)list_size;
  T[3] = (void *)(long)tgl_get_peer_id (id);
  T[4] = (void *)(long)tgl_get_peer_type (id);
  T[5] = (void *)(long)limit;
  T[6] = (void *)(long)offset;
  T[7] = (void *)(long)from;
  T[8] = (void *)(long)to;
  T[9] = s;

  out_string (s);
  out_int (CODE_input_messages_filter_empty);
  out_int (from);
  out_int (to);
  out_int (offset); // offset
  out_int (max_id); // max_id
  out_int (limit);
  tglq_send_query (TLS, TLS->DC_working, packet_ptr - packet_buffer, packet_buffer, &msg_search_methods, T, callback, callback_extra);
}

void tgl_do_msg_search (struct tgl_state *TLS, tgl_peer_id_t id, int from, int to, int limit, int offset, const char *s, void (*callback)(struct tgl_state *TLS, void *callback_extra, int success, int size, struct tgl_message *list[]), void *callback_extra) {
  _tgl_do_msg_search (TLS, id, from, to, limit, offset, 0, tstrdup (s), 0, 0, 0, callback, callback_extra);
}
/* }}} */

/* {{{ Contacts search */
static int contacts_search_on_answer (struct tgl_state *TLS, struct query *q) {
  assert (fetch_int () == CODE_contacts_found);
  assert (fetch_int () == CODE_vector);
  int n = fetch_int ();
  int i;
  for (i = 0; i < n; i++) {
    assert (fetch_int () == (int)CODE_contact_found);
    fetch_int ();
  }
  assert (fetch_int () == CODE_vector);
  n = fetch_int ();

  struct tgl_user **UL = talloc (sizeof (void *) * n);
  for (i = 0; i < n; i++) {
    UL[i] = tglf_fetch_alloc_user (TLS);
  }
  if (q->callback) {
    ((void (*)(struct tgl_state *, void *, int, int, struct tgl_user **))q->callback) (TLS, q->callback_extra, 1, n, UL);
  }
  tfree (UL, sizeof (void *) * n);
  return 0;
}

static struct query_methods contacts_search_methods = {
  .on_answer = contacts_search_on_answer,
  .on_error = q_list_on_error,
  .type = TYPE_TO_PARAM(contacts_found)
};

void tgl_do_contacts_search (struct tgl_state *TLS, int limit, const char *s, void (*callback) (struct tgl_state *, void *callback_extra, int success, int size, struct tgl_user *users[]), void *callback_extra) {
  clear_packet ();
  out_int (CODE_contacts_search);
  out_string (s);
  out_int (limit);
  tglq_send_query (TLS, TLS->DC_working, packet_ptr - packet_buffer, packet_buffer, &contacts_search_methods, 0, callback, callback_extra);
}
/* }}} */

/* {{{ Encr accept */
static int send_encr_accept_on_answer (struct tgl_state *TLS, struct query *q) {
  struct tgl_secret_chat *E = tglf_fetch_alloc_encrypted_chat (TLS);

  if (E->state == sc_ok) {
    tgl_do_send_encr_chat_layer (TLS, E);
  }
  if (q->callback) {
    ((void (*)(struct tgl_state *, void *, int, struct tgl_secret_chat *))q->callback) (TLS, q->callback_extra, E->state == sc_ok, E);
  }
  return 0;
}

static int send_encr_request_on_answer (struct tgl_state *TLS, struct query *q) {
  struct tgl_secret_chat *E = tglf_fetch_alloc_encrypted_chat (TLS);
  
  if (q->callback) {
    ((void (*)(struct tgl_state *, void *, int, struct tgl_secret_chat *))q->callback) (TLS, q->callback_extra, E->state != sc_deleted, E);
  }
  return 0;
}

static int encr_accept_on_error (struct tgl_state *TLS, struct query *q, int error_code, int error_len, const char *error) {
  tgl_peer_t *P = q->extra;
  if (P && P->encr_chat.state != sc_deleted &&  error_code == 400) {
    if (strncmp (error, "ENCRYPTION_DECLINED", 19) == 0) {
      bl_do_encr_chat_delete(TLS, &P->encr_chat);
    }
  }
  if (q->callback) {
    ((void (*)(struct tgl_state *, void *, int, struct tgl_secret_chat *))q->callback) (TLS, q->callback_extra, 0, NULL);
  }
  return 0;
}

static struct query_methods send_encr_accept_methods  = {
  .on_answer = send_encr_accept_on_answer,
  .on_error = encr_accept_on_error,
  .type = TYPE_TO_PARAM(encrypted_chat)
};

static struct query_methods send_encr_request_methods  = {
  .on_answer = send_encr_request_on_answer,
  .on_error = q_ptr_on_error,
  .type = TYPE_TO_PARAM(encrypted_chat)
};

//int encr_root;
//unsigned char *encr_prime;
//int encr_param_version;
//static BN_CTX *ctx;

void tgl_do_send_accept_encr_chat (struct tgl_state *TLS, struct tgl_secret_chat *E, unsigned char *random, void (*callback)(struct tgl_state *TLS,void *callback_extra, int success, struct tgl_secret_chat *E), void *callback_extra) {
  int i;
  int ok = 0;
  for (i = 0; i < 64; i++) {
    if (E->key[i]) {
      ok = 1;
      break;
    }
  }
  if (ok) { 
    if (callback) {
      callback (TLS, callback_extra, 1, E);
    }
    return; 
  } // Already generated key for this chat
  assert (E->g_key);
  assert (TLS->BN_ctx);
  unsigned char random_here[256];
  tglt_secure_random (random_here, 256);
  for (i = 0; i < 256; i++) {
    random[i] ^= random_here[i];
  }
  BIGNUM *b = BN_bin2bn (random, 256, 0);
  ensure_ptr (b);
  BIGNUM *g_a = BN_bin2bn (E->g_key, 256, 0);
  ensure_ptr (g_a);
  assert (tglmp_check_g_a (TLS, TLS->encr_prime_bn, g_a) >= 0);
  //if (!ctx) {
  //  ctx = BN_CTX_new ();
  //  ensure_ptr (ctx);
  //}
  BIGNUM *p = TLS->encr_prime_bn;
  BIGNUM *r = BN_new ();
  ensure_ptr (r);
  ensure (BN_mod_exp (r, g_a, b, p, TLS->BN_ctx));
  static unsigned char kk[256];
  memset (kk, 0, sizeof (kk));
  BN_bn2bin (r, kk + (256 - BN_num_bytes (r)));
  for (i = 0; i < 256; i++) {
    kk[i] ^= E->nonce[i];
  }
  static unsigned char sha_buffer[20];
  sha1 (kk, 256, sha_buffer);

  bl_do_encr_chat_set_key (TLS, E, kk, *(long long *)(sha_buffer + 12));
  bl_do_encr_chat_set_sha (TLS, E, sha_buffer);

  clear_packet ();
  out_int (CODE_messages_accept_encryption);
  out_int (CODE_input_encrypted_chat);
  out_int (tgl_get_peer_id (E->id));
  out_long (E->access_hash);
  
  ensure (BN_set_word (g_a, TLS->encr_root));
  ensure (BN_mod_exp (r, g_a, b, p, TLS->BN_ctx));
  static unsigned char buf[256];
  memset (buf, 0, sizeof (buf));
  BN_bn2bin (r, buf + (256 - BN_num_bytes (r)));
  out_cstring ((void *)buf, 256);

  out_long (E->key_fingerprint);
  BN_clear_free (b);
  BN_clear_free (g_a);
  BN_clear_free (r);

  tglq_send_query (TLS, TLS->DC_working, packet_ptr - packet_buffer, packet_buffer, &send_encr_accept_methods, E, callback, callback_extra);
}

void tgl_do_create_keys_end (struct tgl_state *TLS, struct tgl_secret_chat *U) {
  assert (TLS->encr_prime);
  BIGNUM *g_b = BN_bin2bn (U->g_key, 256, 0);
  ensure_ptr (g_b);
  assert (tglmp_check_g_a (TLS, TLS->encr_prime_bn, g_b) >= 0);
  
  BIGNUM *p = TLS->encr_prime_bn; 
  ensure_ptr (p);
  BIGNUM *r = BN_new ();
  ensure_ptr (r);
  BIGNUM *a = BN_bin2bn ((void *)U->key, 256, 0);
  ensure_ptr (a);
  ensure (BN_mod_exp (r, g_b, a, p, TLS->BN_ctx));

  unsigned char *t = talloc (256);
  memcpy (t, U->key, 256);
  
  memset (U->key, 0, sizeof (U->key));
  BN_bn2bin (r, (void *)(((char *)(U->key)) + (256 - BN_num_bytes (r))));
  int i;
  for (i = 0; i < 64; i++) {
    U->key[i] ^= *(((int *)U->nonce) + i);
  }
  
  static unsigned char sha_buffer[20];
  sha1 ((void *)U->key, 256, sha_buffer);
  long long k = *(long long *)(sha_buffer + 12);
  if (k != U->key_fingerprint) {
    vlogprintf (E_WARNING, "Key fingerprint mismatch (my 0x%llx 0x%llx)\n", (unsigned long long)k, (unsigned long long)U->key_fingerprint);
    U->state = sc_deleted;
  }

  memcpy (U->first_key_sha, sha_buffer, 20);
  tfree_secure (t, 256);
  
  BN_clear_free (g_b);
  BN_clear_free (r);
  BN_clear_free (a);
}

void tgl_do_send_create_encr_chat (struct tgl_state *TLS, void *x, unsigned char *random, void (*callback)(struct tgl_state *TLS, void *callback_extra, int success, struct tgl_secret_chat *E), void *callback_extra) {
  int user_id = (long)x;
  int i;
  unsigned char random_here[256];
  tglt_secure_random (random_here, 256);
  for (i = 0; i < 256; i++) {
    random[i] ^= random_here[i];
  }
  BIGNUM *a = BN_bin2bn (random, 256, 0);
  ensure_ptr (a);
  BIGNUM *p = BN_bin2bn (TLS->encr_prime, 256, 0); 
  ensure_ptr (p);
 
  BIGNUM *g = BN_new ();
  ensure_ptr (g);

  ensure (BN_set_word (g, TLS->encr_root));

  BIGNUM *r = BN_new ();
  ensure_ptr (r);

  ensure (BN_mod_exp (r, g, a, p, TLS->BN_ctx));

  BN_clear_free (a);

  static char g_a[256];
  memset (g_a, 0, 256);

  BN_bn2bin (r, (void *)(g_a + (256 - BN_num_bytes (r))));
  
  int t = lrand48 ();
  while (tgl_peer_get (TLS, TGL_MK_ENCR_CHAT (t))) {
    t = lrand48 ();
  }

  bl_do_encr_chat_init (TLS, t, user_id, (void *)random, (void *)g_a);
  tgl_peer_t *_E = tgl_peer_get (TLS, TGL_MK_ENCR_CHAT (t));
  assert (_E);
  struct tgl_secret_chat *E = &_E->encr_chat;
  
  clear_packet ();
  out_int (CODE_messages_request_encryption);
  tgl_peer_t *U = tgl_peer_get (TLS, TGL_MK_USER (E->user_id));
  assert (U);
  if (U && U->user.access_hash) {
    out_int (CODE_input_user_foreign);
    out_int (E->user_id);
    out_long (U->user.access_hash);
  } else {
    out_int (CODE_input_user_contact);
    out_int (E->user_id);
  }
  out_int (tgl_get_peer_id (E->id));
  out_cstring (g_a, 256);
  //write_secret_chat_file ();
  
  BN_clear_free (g);
  BN_clear_free (p);
  BN_clear_free (r);

  tglq_send_query (TLS, TLS->DC_working, packet_ptr - packet_buffer, packet_buffer, &send_encr_request_methods, E, callback, callback_extra);
}

static int get_dh_config_on_answer (struct tgl_state *TLS, struct query *q) {
  unsigned x = fetch_int ();
  assert (x == CODE_messages_dh_config || x == CODE_messages_dh_config_not_modified);
  if (x == CODE_messages_dh_config)  {
    int a = fetch_int ();
    int l = prefetch_strlen ();
    assert (l == 256);
    char *s = fetch_str (l);
    int v = fetch_int ();
    bl_do_set_dh_params (TLS, a, (void *)s, v);

    BIGNUM *p = BN_bin2bn ((void *)s, 256, 0);
    ensure_ptr (p);
    assert (tglmp_check_DH_params (TLS, p, a) >= 0);
    BN_free (p);      
  } else {
    assert (TLS->encr_param_version);
  }
  int l = prefetch_strlen ();
  assert (l == 256);
  unsigned char *random = talloc (256);
  memcpy (random, fetch_str (256), 256);
  if (q->extra) {
    void **x = q->extra;
    ((void (*)(struct tgl_state *, void *, void *, void *, void *))(*x))(TLS, x[1], random, q->callback, q->callback_extra);
    tfree (x, 2 * sizeof (void *));
    tfree_secure (random, 256);
  } else {
    tfree_secure (random, 256);
  }
  return 0;
}

static struct query_methods get_dh_config_methods  = {
  .on_answer = get_dh_config_on_answer,
  .on_error = q_void_on_error,
  .type = TYPE_TO_PARAM(messages_dh_config)
};

void tgl_do_accept_encr_chat_request (struct tgl_state *TLS, struct tgl_secret_chat *E, void (*callback)(struct tgl_state *TLS, void *callback_extra, int success, struct tgl_secret_chat *E), void *callback_extra) {
  if (E->state != sc_request) {
    if (callback) {
      callback (TLS, callback_extra, 0, E);
    }
    return;
  }
  assert (E->state == sc_request);
  
  clear_packet ();
  out_int (CODE_messages_get_dh_config);
  out_int (TLS->encr_param_version);
  out_int (256);
  void **x = talloc (2 * sizeof (void *));
  x[0] = tgl_do_send_accept_encr_chat;
  x[1] = E;
  tglq_send_query (TLS, TLS->DC_working, packet_ptr - packet_buffer, packet_buffer, &get_dh_config_methods, x, callback, callback_extra);
}

void tgl_do_create_encr_chat_request (struct tgl_state *TLS, int user_id, void (*callback)(struct tgl_state *TLS, void *callback_extra, int success, struct tgl_secret_chat *E), void *callback_extra) {
  clear_packet ();
  out_int (CODE_messages_get_dh_config);
  out_int (TLS->encr_param_version);
  out_int (256);
  void **x = talloc (2 * sizeof (void *));
  x[0] = tgl_do_send_create_encr_chat;
  x[1] = (void *)(long)(user_id);
  tglq_send_query (TLS, TLS->DC_working, packet_ptr - packet_buffer, packet_buffer, &get_dh_config_methods, x, callback, callback_extra);
}
/* }}} */

/* {{{ Get difference */
//int unread_messages;
//int difference_got;
//int seq, pts, qts, last_date;
static int get_state_on_answer (struct tgl_state *TLS, struct query *q) {
  assert (TLS->locks & TGL_LOCK_DIFF);
  TLS->locks ^= TGL_LOCK_DIFF;
  assert (fetch_int () == (int)CODE_updates_state);
  bl_do_set_pts (TLS, fetch_int ());
  bl_do_set_qts (TLS, fetch_int ());
  bl_do_set_date (TLS, fetch_int ());
  bl_do_set_seq (TLS, fetch_int ());
  //unread_messages = fetch_int ();
  fetch_int ();
  //write_state_file ();
  //difference_got = 1;

  if (q->callback) {
    ((void (*)(struct tgl_state *, void *, int))q->callback) (TLS, q->callback_extra, 1);
  }
  return 0;
}

static int lookup_state_on_answer (struct tgl_state *TLS, struct query *q) {
  assert (fetch_int () == (int)CODE_updates_state);
  int pts = fetch_int ();
  int qts = fetch_int ();
  fetch_int ();
  int seq = fetch_int ();
  fetch_int ();

  if (pts > TLS->pts || qts > TLS->qts || seq > TLS->seq) {
    tgl_do_get_difference (TLS, 0, 0, 0);
  }
  return 0;
}


//int get_difference_active;
static int get_difference_on_answer (struct tgl_state *TLS, struct query *q) {
  //get_difference_active = 0;
  assert (TLS->locks & TGL_LOCK_DIFF);
  TLS->locks ^= TGL_LOCK_DIFF;

  unsigned x = fetch_int ();
  if (x == CODE_updates_difference_empty) {
    bl_do_set_date (TLS, fetch_int ());
    bl_do_set_seq (TLS, fetch_int ());
    //difference_got = 1;
    
    vlogprintf (E_DEBUG, "Empty difference. Seq = %d\n", TLS->seq);
    if (q->callback) {
      ((void (*)(struct tgl_state *, void *, int))q->callback) (TLS, q->callback_extra, 1);
    }
  } else if (x == CODE_updates_difference || x == CODE_updates_difference_slice) {
    int n, i;
    assert (fetch_int () == CODE_vector);
    n = fetch_int ();
    struct tgl_message **ML = talloc (n * sizeof (void *));
    int ml_pos = 0;
    for (i = 0; i < n; i++) {
      ML[ml_pos ++] = tglf_fetch_alloc_message (TLS);
    }
    assert (fetch_int () == CODE_vector);
    n = fetch_int ();
    struct tgl_message **EL = talloc (n * sizeof (void *));
    int el_pos = 0;
    for (i = 0; i < n; i++) {
      EL[el_pos ++] = tglf_fetch_alloc_encrypted_message (TLS);
    }
    assert (fetch_int () == CODE_vector);
    n = fetch_int ();
    for (i = 0; i < n; i++) {
      tglu_work_update (TLS, 0, 0);
    }
    assert (fetch_int () == CODE_vector);
    n = fetch_int ();
    for (i = 0; i < n; i++) {
      tglf_fetch_alloc_chat (TLS);
    }
    assert (fetch_int () == CODE_vector);
    n = fetch_int ();
    for (i = 0; i < n; i++) {
      tglf_fetch_alloc_user (TLS);
    }
    assert (fetch_int () == (int)CODE_updates_state);
    bl_do_set_pts (TLS, fetch_int ());
    bl_do_set_qts (TLS, fetch_int ());
    bl_do_set_date (TLS, fetch_int ());
    if (x == CODE_updates_difference) {
      bl_do_set_seq (TLS, fetch_int ());
      vlogprintf (E_DEBUG, "Difference end. New seq = %d\n", TLS->seq);
    } else {
      fetch_int ();
    }
    //unread_messages = fetch_int ();
    fetch_int ();
    //write_state_file ();
    /*for (i = 0; i < ml_pos; i++) {
      print_message (ML[i]);
    }*/
    for (i = 0; i < ml_pos; i++) {
      //TLS->callback.new_msg (ML[i]);
      bl_do_msg_update (TLS, ML[i]->id);
    }
    for (i = 0; i < el_pos; i++) {
      //TLS->callback.new_msg (EL[i]);
      bl_do_msg_update (TLS, EL[i]->id);
    }
    tfree (ML, ml_pos * sizeof (void *));
    tfree (EL, el_pos * sizeof (void *));

    if (x == CODE_updates_difference_slice) {
      //if (q->callback) {
      //  ((void (*)(void *, int))q->callback) (q->callback_extra, 1);
      //}
      tgl_do_get_difference (TLS, 0, q->callback, q->callback_extra);
    } else {
      //difference_got = 1;
      if (q->callback) {
        ((void (*)(struct tgl_state *, void *, int))q->callback) (TLS, q->callback_extra, 1);
      }
    }
  } else {
    assert (0);
  }
  return 0;   
}

static struct query_methods lookup_state_methods = {
  .on_answer = lookup_state_on_answer,
  .on_error = q_void_on_error,
  .type = TYPE_TO_PARAM(updates_state)
};

static struct query_methods get_state_methods = {
  .on_answer = get_state_on_answer,
  .on_error = q_void_on_error,
  .type = TYPE_TO_PARAM(updates_state)
};

static struct query_methods get_difference_methods = {
  .on_answer = get_difference_on_answer,
  .on_error = q_void_on_error,
  .type = TYPE_TO_PARAM(updates_difference)
};

void tgl_do_lookup_state (struct tgl_state *TLS) {
  if (TLS->locks & TGL_LOCK_DIFF) {
    return;
  }
  clear_packet ();
  tgl_do_insert_header (TLS);
  out_int (CODE_updates_get_state);
  tglq_send_query (TLS, TLS->DC_working, packet_ptr - packet_buffer, packet_buffer, &lookup_state_methods, 0, 0, 0);
}

void tgl_do_get_difference (struct tgl_state *TLS, int sync_from_start, void (*callback)(struct tgl_state *TLS, void *callback_extra, int success), void *callback_extra) {
  //get_difference_active = 1;
  //difference_got = 0;
  if (TLS->locks & TGL_LOCK_DIFF) {
    if (callback) {
      callback (TLS, callback_extra, 0);
    }
    return;
  }
  TLS->locks |= TGL_LOCK_DIFF;
  clear_packet ();
  tgl_do_insert_header (TLS);
  if (TLS->pts > 0 || sync_from_start) {
    if (TLS->pts == 0) { TLS->pts = 1; }
    //if (TLS->qts == 0) { TLS->qts = 1; }
    if (TLS->date == 0) { TLS->date = 1; }
    out_int (CODE_updates_get_difference);
    out_int (TLS->pts);
    out_int (TLS->date);
    out_int (TLS->qts);
    tglq_send_query (TLS, TLS->DC_working, packet_ptr - packet_buffer, packet_buffer, &get_difference_methods, 0, callback, callback_extra);
  } else {
    out_int (CODE_updates_get_state);
    tglq_send_query (TLS, TLS->DC_working, packet_ptr - packet_buffer, packet_buffer, &get_state_methods, 0, callback, callback_extra);
  }
}
/* }}} */

/* {{{ Visualize key */
/*char *colors[4] = {COLOR_GREY, COLOR_CYAN, COLOR_BLUE, COLOR_GREEN};

void tgl_do_visualize_key (tgl_peer_id_t id) {
  assert (tgl_get_peer_type (id) == TGL_PEER_ENCR_CHAT);
  tgl_peer_t *P = tgl_peer_get (TLS, id);
  assert (P);
  if (P->encr_chat.state != sc_ok) {
    rprintf ("Chat is not initialized yet\n");
    return;
  }
  unsigned char buf[20];
  SHA1 ((void *)P->encr_chat.key, 256, buf);
  print_start ();
  int i;
  for (i = 0; i < 16; i++) {
    int x = buf[i];
    int j;
    for (j = 0; j < 4; j ++) {    
      push_color (colors[x & 3]);
      push_color (COLOR_INVERSE);
      printf ("  ");
      pop_color ();
      pop_color ();
      x = x >> 2;
    }
    if (i & 1) { printf ("\n"); }
  }
  print_end ();
}*/

void tgl_do_visualize_key (struct tgl_state *TLS, tgl_peer_id_t id, unsigned char buf[16]) {
  assert (tgl_get_peer_type (id) == TGL_PEER_ENCR_CHAT);
  tgl_peer_t *P = tgl_peer_get (TLS, id);
  assert (P);
  if (P->encr_chat.state != sc_ok) {
    vlogprintf (E_WARNING, "Chat is not initialized yet\n");
    return;
  }
  //unsigned char res[20];
  //SHA1 ((void *)P->encr_chat.key, 256, res);
  //memcpy (buf, res, 16);
  memcpy (buf, P->encr_chat.first_key_sha, 16);
}
/* }}} */

/* {{{ Add user to chat */

static struct query_methods add_user_to_chat_methods = {
  .on_answer = fwd_msg_on_answer,
  .on_error = q_ptr_on_error,
  .type = TYPE_TO_PARAM(messages_stated_message)
};

void tgl_do_add_user_to_chat (struct tgl_state *TLS, tgl_peer_id_t chat_id, tgl_peer_id_t id, int limit, void (*callback)(struct tgl_state *TLS, void *callback_extra, int success, struct tgl_message *M), void *callback_extra) {
  clear_packet ();
  out_int (CODE_messages_add_chat_user);
  out_int (tgl_get_peer_id (chat_id));
  
  assert (tgl_get_peer_type (id) == TGL_PEER_USER);
  tgl_peer_t *U = tgl_peer_get (TLS, id);
  if (U && U->user.access_hash) {
    out_int (CODE_input_user_foreign);
    out_int (tgl_get_peer_id (id));
    out_long (U->user.access_hash);
  } else {
    out_int (CODE_input_user_contact);
    out_int (tgl_get_peer_id (id));
  }
  out_int (limit);
  tglq_send_query (TLS, TLS->DC_working, packet_ptr - packet_buffer, packet_buffer, &add_user_to_chat_methods, 0, callback, callback_extra);
}

void tgl_do_del_user_from_chat (struct tgl_state *TLS, tgl_peer_id_t chat_id, tgl_peer_id_t id, void (*callback)(struct tgl_state *TLS, void *callback_extra, int success, struct tgl_message *M), void *callback_extra) {
  clear_packet ();
  out_int (CODE_messages_delete_chat_user);
  out_int (tgl_get_peer_id (chat_id));
  
  assert (tgl_get_peer_type (id) == TGL_PEER_USER);
  tgl_peer_t *U = tgl_peer_get (TLS, id);
  if (U && U->user.access_hash) {
    out_int (CODE_input_user_foreign);
    out_int (tgl_get_peer_id (id));
    out_long (U->user.access_hash);
  } else {
    out_int (CODE_input_user_contact);
    out_int (tgl_get_peer_id (id));
  }
  tglq_send_query (TLS, TLS->DC_working, packet_ptr - packet_buffer, packet_buffer, &add_user_to_chat_methods, 0, callback, callback_extra);
}
/* }}} */

/* {{{ Create secret chat */
//char *create_print_name (tgl_peer_id_t id, const char *a1, const char *a2, const char *a3, const char *a4);

void tgl_do_create_secret_chat (struct tgl_state *TLS, tgl_peer_id_t id, void (*callback)(struct tgl_state *TLS, void *callback_extra, int success, struct tgl_secret_chat *E), void *callback_extra) {
  assert (tgl_get_peer_type (id) == TGL_PEER_USER);
  tgl_peer_t *U = tgl_peer_get (TLS, id);
  if (!U) { 
    vlogprintf (E_WARNING, "Can not create chat with unknown user\n");
    return;
  }

  tgl_do_create_encr_chat_request (TLS, tgl_get_peer_id (id), callback, callback_extra); 
}
/* }}} */

/* {{{ Create group chat */
static struct query_methods create_group_chat_methods = {
  .on_answer = fwd_msg_on_answer,
  .on_error = q_ptr_on_error,
  .type = TYPE_TO_PARAM(messages_stated_message)
};

void tgl_do_create_group_chat (struct tgl_state *TLS, tgl_peer_id_t id, const char *chat_topic, void (*callback)(struct tgl_state *TLS, void *callback_extra, int success, struct tgl_message *M), void *callback_extra) {
  assert (tgl_get_peer_type (id) == TGL_PEER_USER);
  tgl_peer_t *U = tgl_peer_get (TLS, id);
  if (!U) { 
    vlogprintf (E_WARNING, "Can not create chat with unknown user\n");
    if (callback) {
      callback (TLS, callback_extra, 0, 0);
    }
    return;
  }
  clear_packet ();
  out_int (CODE_messages_create_chat);
  out_int (CODE_vector);
  out_int (1); // Number of users, currently we support only 1 user.
  if (U && U->user.access_hash) {
    out_int (CODE_input_user_foreign);
    out_int (tgl_get_peer_id (id));
    out_long (U->user.access_hash);
  } else {
    out_int (CODE_input_user_contact);
    out_int (tgl_get_peer_id (id));
  }
  out_string (chat_topic);
  tglq_send_query (TLS, TLS->DC_working, packet_ptr - packet_buffer, packet_buffer, &create_group_chat_methods, 0, callback, callback_extra);
}

void tgl_do_create_group_chat_ex (struct tgl_state *TLS, int users_num, tgl_peer_id_t ids[], const char *chat_topic, void (*callback)(struct tgl_state *TLS, void *callback_extra, int success, struct tgl_message *M), void *callback_extra) {
  clear_packet ();
  out_int (CODE_messages_create_chat);
  out_int (CODE_vector);
  out_int (users_num); // Number of users, currently we support only 1 user.
  int i;
  for (i = 0; i < users_num; i++) {
    tgl_peer_id_t id = ids[i];
    tgl_peer_t *U = tgl_peer_get (TLS, id);
    if (!U || tgl_get_peer_type (id) != TGL_PEER_USER) { 
      vlogprintf (E_WARNING, "Can not create chat with unknown user\n");
      if (callback) {
        callback (TLS, callback_extra, 0, 0);
      }
      return;
    }
    if (U && U->user.access_hash) {
      out_int (CODE_input_user_foreign);
      out_int (tgl_get_peer_id (id));
      out_long (U->user.access_hash);
    } else {
      out_int (CODE_input_user_contact);
      out_int (tgl_get_peer_id (id));
    }
  }
  out_string (chat_topic);
  tglq_send_query (TLS, TLS->DC_working, packet_ptr - packet_buffer, packet_buffer, &create_group_chat_methods, 0, callback, callback_extra);
}
/* }}} */

/* {{{ Delete msg */

static int delete_msg_on_answer (struct tgl_state *TLS, struct query *q) {
  assert (fetch_int () == CODE_vector);
  int n = fetch_int ();
  fetch_skip (n);

  if (q->callback) {
    ((void (*)(struct tgl_state *, void *, int))q->callback) (TLS, q->callback_extra, 1);
  }
  return 0;
}

static struct query_methods delete_msg_methods = {
  .on_answer = delete_msg_on_answer,
  .on_error = q_void_on_error,
  .type = TYPE_TO_PARAM_1(vector, TYPE_TO_PARAM (bare_int))
};

void tgl_do_delete_msg (struct tgl_state *TLS, long long id, void (*callback)(struct tgl_state *TLS, void *callback_extra, int success), void *callback_extra) {
  clear_packet ();
  out_int (CODE_messages_delete_messages);
  out_int (CODE_vector);
  out_int (1);
  out_int (id);
  tglq_send_query (TLS, TLS->DC_working, packet_ptr - packet_buffer, packet_buffer, &delete_msg_methods, 0, callback, callback_extra);
}
/* }}} */

/* {{{ Restore msg */

static int restore_msg_on_answer (struct tgl_state *TLS, struct query *q) {
  assert (fetch_int () == CODE_vector);
  int n = fetch_int ();
  fetch_skip (n);
  //logprintf ("Restored %d messages\n", n);
  
  if (q->callback) {
    ((void (*)(struct tgl_state *, void *, int))q->callback) (TLS, q->callback_extra, 1);
  }
  return 0;
}

static struct query_methods restore_msg_methods = {
  .on_answer = restore_msg_on_answer,
  .on_error = q_void_on_error,
  .type = TYPE_TO_PARAM_1(vector, TYPE_TO_PARAM (bare_int))
};

void tgl_do_restore_msg (struct tgl_state *TLS, long long id, void (*callback)(struct tgl_state *TLS, void *callback_extra, int success), void *callback_extra) {
  clear_packet ();
  out_int (CODE_messages_restore_messages);
  out_int (CODE_vector);
  out_int (1);
  out_int (id);
  tglq_send_query (TLS, TLS->DC_working, packet_ptr - packet_buffer, packet_buffer, &restore_msg_methods, 0, callback, callback_extra);
}
/* }}} */

/* {{{ Export card */

static int export_card_on_answer (struct tgl_state *TLS, struct query *q) {
  assert (fetch_int () == CODE_vector);
  int n = fetch_int ();
  //logprintf ("Restored %d messages\n", n);
  int *r = talloc (4 * n);
  fetch_ints (r, n);
  
  if (q->callback) {
    ((void (*)(struct tgl_state *, void *, int, int, int *))q->callback) (TLS, q->callback_extra, 1, n, r);
  }
  free (r);
  return 0;
}

static struct query_methods export_card_methods = {
  .on_answer = export_card_on_answer,
  .on_error = q_list_on_error,
  .type = TYPE_TO_PARAM_1(vector, TYPE_TO_PARAM (bare_int))
};

void tgl_do_export_card (struct tgl_state *TLS, void (*callback)(struct tgl_state *TLS, void *callback_extra, int success, int size, int *card), void *callback_extra) {
  clear_packet ();
  out_int (CODE_contacts_export_card);
  tglq_send_query (TLS, TLS->DC_working, packet_ptr - packet_buffer, packet_buffer, &export_card_methods, 0, callback, callback_extra);
}
/* }}} */

/* {{{ Import card */

static int import_card_on_answer (struct tgl_state *TLS, struct query *q) {
  struct tgl_user *U = tglf_fetch_alloc_user (TLS);
  
  if (q->callback) {
    ((void (*)(struct tgl_state *, void *, int, struct tgl_user *))q->callback) (TLS, q->callback_extra, 1, U);
  }
  return 0;
}

static struct query_methods import_card_methods = {
  .on_answer = import_card_on_answer,
  .on_error = q_ptr_on_error, 
  .type = TYPE_TO_PARAM (user)
};

void tgl_do_import_card (struct tgl_state *TLS, int size, int *card, void (*callback)(struct tgl_state *TLS, void *callback_extra, int success, struct tgl_user *U), void *callback_extra) {
  clear_packet ();
  out_int (CODE_contacts_import_card);
  out_int (CODE_vector);
  out_int (size);
  out_ints (card, size);
  tglq_send_query (TLS, TLS->DC_working, packet_ptr - packet_buffer, packet_buffer, &import_card_methods, 0, callback, callback_extra);
}
/* }}} */

/* {{{ Send typing */
static int send_typing_on_answer (struct tgl_state *TLS, struct query *q) {
  fetch_bool ();
  if (q->callback) {
    ((void (*)(struct tgl_state *, void *, int))q->callback)(TLS, q->callback_extra, 1);
  }
  return 0;
}

static struct query_methods send_typing_methods = {
  .on_answer = send_typing_on_answer,
  .on_error = q_void_on_error,
  .type = TYPE_TO_PARAM(bool)
};

void tgl_do_send_typing (struct tgl_state *TLS, tgl_peer_id_t id, enum tgl_typing_status status, void (*callback)(struct tgl_state *TLS, void *callback_extra, int success), void *callback_extra) {
  if (tgl_get_peer_type (id) != TGL_PEER_ENCR_CHAT) {  
    clear_packet ();
    out_int (CODE_messages_set_typing);
    out_peer_id (TLS, id);
    switch (status) {
    case tgl_typing_none:
    case tgl_typing_typing:
      out_int (CODE_send_message_typing_action);
      break;
    case tgl_typing_cancel:
      out_int (CODE_send_message_cancel_action);
      break;
    case tgl_typing_record_video:
      out_int (CODE_send_message_record_video_action);
      break;
    case tgl_typing_upload_video:
      out_int (CODE_send_message_upload_video_action);
      break;
    case tgl_typing_record_audio:
      out_int (CODE_send_message_record_audio_action);
      break;
    case tgl_typing_upload_audio:
      out_int (CODE_send_message_upload_audio_action);
      break;
    case tgl_typing_upload_photo:
      out_int (CODE_send_message_upload_photo_action);
      break;
    case tgl_typing_upload_document:
      out_int (CODE_send_message_upload_document_action);
      break;
    case tgl_typing_geo:
      out_int (CODE_send_message_geo_location_action);
      break;
    case tgl_typing_choose_contact:
      out_int (CODE_send_message_choose_contact_action);
      break;
    }
    tglq_send_query (TLS, TLS->DC_working, packet_ptr - packet_buffer, packet_buffer, &send_typing_methods, 0, callback, callback_extra);
  } else {
    if (callback) {
      callback (TLS, callback_extra, 0);
    }
  }
}
/* }}} */

/* {{{ Extd query */
#ifndef DISABLE_EXTF
static int ext_query_on_answer (struct tgl_state *TLS, struct query *q) {
  if (q->callback) {
    char *buf = tglf_extf_fetch (TLS, q->type);
    ((void (*)(struct tgl_state *, void *, int, char *))q->callback) (TLS, q->callback_extra, 1, buf);
  }
  tgl_paramed_type_free (q->type);
  return 0;
}

static struct query_methods ext_query_methods = {
  .on_answer = ext_query_on_answer,
  .on_error = q_list_on_error
};

void tgl_do_send_extf (struct tgl_state *TLS, const char *data, int data_len, void (*callback)(struct tgl_state *TLS, void *callback_extra, int success, char *buf), void *callback_extra) {
  clear_packet ();

  ext_query_methods.type = tglf_extf_store (TLS, data, data_len);

  if (ext_query_methods.type) { 
    tglq_send_query (TLS, TLS->DC_working, packet_ptr - packet_buffer, packet_buffer, &ext_query_methods, 0, callback, callback_extra);
  }
}
#else
void tgl_do_send_extf (struct tgl_state *TLS, const char *data, int data_len, void (*callback)(struct tgl_state *TLS, void *callback_extra, int success, char *buf), void *callback_extra) {
  if (callback) {
    callback (TLS, callback_extra, 0, 0);
  }
}
#endif
/* }}} */

static int set_password_on_answer (struct tgl_state *TLS, struct query *q) {
  fetch_bool ();
  if (q->callback) {
    ((void (*)(struct tgl_state *, void *, int))q->callback)(TLS, q->callback_extra, 1);
  }
  return 0;
}

static int set_password_on_error (struct tgl_state *TLS, struct query *q, int error_code, int l, const char *error) {
  if (error_code == 400) {
    if (!strcmp (error, "PASSWORD_HASH_INVALID")) {
      vlogprintf (E_WARNING, "Bad old password\n");
      if (q->callback) {
        ((void (*)(struct tgl_state *, void *, int))q->callback)(TLS, q->callback_extra, 0);
      }
      return 0;
    }
    if (!strcmp (error, "NEW_PASSWORD_BAD")) {
      vlogprintf (E_WARNING, "Bad new password (unchanged or equals hint)\n");
      if (q->callback) {
        ((void (*)(struct tgl_state *, void *, int))q->callback)(TLS, q->callback_extra, 0);
      }
      return 0;
    }
    if (!strcmp (error, "NEW_SALT_INVALID")) {
      vlogprintf (E_WARNING, "Bad new salt\n");
      if (q->callback) {
        ((void (*)(struct tgl_state *, void *, int))q->callback)(TLS, q->callback_extra, 0);
      }
      return 0;
    }
  }
  if (q->callback) {
    ((void (*)(struct tgl_state *, void *, int))q->callback)(TLS, q->callback_extra, 0);
  }
  return 0;
}

static struct query_methods set_password_methods = {
  .on_answer = set_password_on_answer,
  .on_error = set_password_on_error,
  .type = TYPE_TO_PARAM(bool)
};

static void tgl_do_act_set_password (struct tgl_state *TLS, const char *current_password, const char *new_password, const char *current_salt, int l, const char *new_salt, int l2, const char *hint, void (*callback)(struct tgl_state *TLS, void *callback_extra, int success), void *callback_extra) {
  clear_packet ();
  static char s[512];
  static unsigned char shab[32];

  if (current_password && current_salt) {
    assert (strlen (current_salt) <= 128);
    assert (strlen (current_password) <= 128);
  }
  assert (strlen (new_salt) <= 128);
  assert (strlen (new_password) <= 128);

  out_int (CODE_account_set_password);

  if (current_password && current_salt) {
    memcpy (s, current_salt, l);
    
    int r = strlen (current_password);
    strcpy (s + l, current_password);
  
    memcpy (s + l + r, current_salt, l);

    SHA256 ((void *)s, 2 * l + r, shab);
    out_cstring ((void *)shab, 32);
  } else {
    out_string ("");
  }

  if (new_password && strlen (new_password)) {
    static char d[256];
    memcpy (d, new_salt, l2);
    int l = l2;
    tglt_secure_random (d + l, 16);
    l += 16;
    memcpy (s, d, l);
    
    int r = strlen (new_password);
    strcpy (s + l, new_password);
  
    memcpy (s + l + r, d, l);

    SHA256 ((void *)s, 2 * l + r, shab);
    
    out_cstring (d, l);
    out_cstring ((void *)shab, 32);
  } else {
    out_string (new_salt);
    out_string ("");
  }

  out_string (hint);
    
  tglq_send_query (TLS, TLS->DC_working, packet_ptr - packet_buffer, packet_buffer, &set_password_methods, 0, callback, callback_extra);
}

void tgl_on_new_pwd (struct tgl_state *TLS, const char *pwd, void *_T);
void tgl_on_new2_pwd (struct tgl_state *TLS, const char *pwd, void *_T) {
  void **T = _T;
  if (strcmp (T[6], pwd)) {
    tfree_str (T[6]);
    T[6] = NULL;
    vlogprintf (E_ERROR, "passwords do not match\n");
    TLS->callback.get_string (TLS, "new password: ", 1, tgl_on_new_pwd, T);
    return;
  }
  tgl_do_act_set_password (TLS, T[5], T[6], T[1], (long)T[0], T[3], (long)T[2], T[4], T[7], T[8]);
  tfree (T[1], (long)T[0]);
  tfree (T[3], (long)T[2]);
  tfree_str (T[4]);
  tfree_str (T[5]);
  tfree_str (T[6]);
  tfree (T, sizeof (void *) * 9);
}

void tgl_on_new_pwd (struct tgl_state *TLS, const char *pwd, void *_T) {
  void **T = _T;
  T[6] = tstrdup (pwd);
  TLS->callback.get_string (TLS, "retype new password: ", 1, tgl_on_new2_pwd, T);
}

void tgl_on_old_pwd (struct tgl_state *TLS, const char *pwd, void *_T) {
  void **T = _T;
  T[5] = tstrdup (pwd);
  TLS->callback.get_string (TLS, "new password: ", 1, tgl_on_new_pwd, T);
}

static int set_get_password_on_answer (struct tgl_state *TLS, struct query *q) {
  unsigned x = fetch_int ();
  assert (x == CODE_account_password || x == CODE_account_no_password);

  char *new_salt = "";
  char *current_salt = NULL;

  char *hint = NULL;
  int l = 0;
  int l2 = 0;
  if (x == CODE_account_no_password) {
    l2 = prefetch_strlen ();
    new_salt = fetch_str (l2);
  } else {
    l = prefetch_strlen ();
    current_salt = fetch_str (l);
    
    l2 = prefetch_strlen ();
    new_salt = fetch_str (l2);
    
    hint = fetch_str_dup ();
  }

  char *new_hint = q->extra;
  void **T = talloc0 (sizeof (void *) * 9);
  T[0] = (void *)(long)l;
  T[1] = talloc (l);
  memcpy (T[1], current_salt, l);
  T[2] = (void *)(long)l2;
  T[3] = talloc (l2);
  memcpy (T[3], new_salt, l2);
  T[4] = new_hint;
  T[7] = q->callback;
  T[8] = q->callback_extra;

  if (x == CODE_account_no_password) {
    TLS->callback.get_string (TLS, "new password: ", 1, tgl_on_new_pwd, T);
  } else {
    static char s[512];
    snprintf (s, 511, "old password (hint %s): ", hint);
    TLS->callback.get_string (TLS, s, 1, tgl_on_old_pwd, T);
  }
  return 0;
}

static struct query_methods set_get_password_methods = {
  .on_answer = set_get_password_on_answer,
  .on_error = q_void_on_error,
  .type = TYPE_TO_PARAM(account_password)
};

void tgl_do_set_password (struct tgl_state *TLS, const char *hint, void (*callback)(struct tgl_state *TLS, void *extra, int success), void *callback_extra) {
  clear_packet ();
  out_int (CODE_account_get_password);
  tglq_send_query (TLS, TLS->DC_working, packet_ptr - packet_buffer, packet_buffer, &set_get_password_methods, hint ? tstrdup (hint) : NULL, callback, callback_extra);
}

static int check_password_on_error (struct tgl_state *TLS, struct query *q, int error_code, int error_len, const char *error) {
  if (error_code == 400) {
    vlogprintf (E_ERROR, "bad password\n");
    tgl_do_check_password (TLS, q->callback, q->callback_extra);
    return 0;
  }
  TLS->locks ^= TGL_LOCK_PASSWORD;
  if (q->callback) {
    ((void (*)(struct tgl_state *, void *, int))q->callback)(TLS, q->callback_extra, 0);
  }
  return 0;
}

static int check_password_on_answer (struct tgl_state *TLS, struct query *q) {
  assert (skip_type_any (TYPE_TO_PARAM (auth_authorization)) >= 0);
  TLS->locks ^= TGL_LOCK_PASSWORD;
  if (q->callback) {
    ((void (*)(struct tgl_state *, void *, int))q->callback)(TLS, q->callback_extra, 1);
  }
  return 0;
}

static struct query_methods check_password_methods = {
  .on_answer = check_password_on_answer,
  .on_error = check_password_on_error,
  .type = TYPE_TO_PARAM(auth_authorization)
};


static void tgl_pwd_got (struct tgl_state *TLS, const char *pwd, void *_T) {
  void **T = _T;
  
  clear_packet ();
  static char s[512];
  static unsigned char shab[32];

  const char *current_password = pwd;
  char *current_salt = T[1];
  int current_salt_len = (long)T[0];

  if (current_password && current_salt) {
    assert (current_salt_len <= 128);
    assert (strlen (current_password) <= 128);
  }

  out_int (CODE_auth_check_password);

  if (current_password && current_salt) {
    int l = current_salt_len;
    memcpy (s, current_salt, l);
    
    int r = strlen (current_password);
    strcpy (s + l, current_password);
  
    memcpy (s + l + r, current_salt, l);

    SHA256 ((void *)s, 2 * l + r, shab);
    out_cstring ((void *)shab, 32);
  } else {
    out_string ("");
  }

  tfree (T[1], (long)T[0]);
  tfree_str (T[2]);
  
  void *cb = T[3];
  void *cbe = T[4];
  
  tfree (T, sizeof (void *) * 5);

  tglq_send_query (TLS, TLS->DC_working, packet_ptr - packet_buffer, packet_buffer, &check_password_methods, 0, cb, cbe);
}

static int check_get_password_on_error (struct tgl_state *TLS, struct query *q, int error_code, int error_len, const char *error) {
  TLS->locks ^= TGL_LOCK_PASSWORD;
  if (q->callback) {
    ((void (*)(struct tgl_state *, void *, int))q->callback) (TLS, q->callback_extra, 0);
  }
  return 0;
}

static int check_get_password_on_answer (struct tgl_state *TLS, struct query *q) {
  unsigned x = fetch_int ();
  assert (x == CODE_account_password || x == CODE_account_no_password);

  char *current_salt = NULL;

  char *hint = NULL;
  int l = 0;
  int l2 = 0;
  if (x == CODE_account_no_password) {
    l2 = prefetch_strlen ();
    fetch_str (l2);
  } else {
    l = prefetch_strlen ();
    current_salt = fetch_str (l);
    
    l2 = prefetch_strlen ();
    fetch_str (l2);
    
    hint = fetch_str_dup ();
  }

  if (x == CODE_account_no_password) {
    TLS->locks ^= TGL_LOCK_PASSWORD;
    return 0;
  }
  static char s[512];
  snprintf (s, 511, "type password (hint %s): ", hint);

  void **T = talloc0 (sizeof (void *) * 5);
  T[0] = (void *)(long)l;
  T[1] = talloc (l);
  memcpy (T[1], current_salt, l);
  T[2] = hint;
  T[3] = q->callback;
  T[4] = q->callback_extra;

  TLS->callback.get_string (TLS, s, 1, tgl_pwd_got, T);
  return 0;
}

static struct query_methods check_get_password_methods = {
  .on_answer = check_get_password_on_answer,
  .on_error = check_get_password_on_error,
  .type = TYPE_TO_PARAM(account_password)
};

void tgl_do_check_password (struct tgl_state *TLS, void (*callback)(struct tgl_state *TLS, void *extra, int success), void *callback_extra) {
  clear_packet ();
  out_int (CODE_account_get_password);
  tglq_send_query (TLS, TLS->DC_working, packet_ptr - packet_buffer, packet_buffer, &check_get_password_methods, NULL, callback, callback_extra);
}

static int send_broadcast_on_answer (struct tgl_state *TLS, struct query *q) {
  unsigned op = fetch_int ();
  assert (op == CODE_messages_stated_messages || op == CODE_messages_stated_messages_links);
  assert (fetch_int () == CODE_vector);
  int num = fetch_int ();
  struct tgl_message **ML = talloc (sizeof (void *) * num);
  int i;
  for (i = 0; i < num; i++) {
    ML[i] = tglf_fetch_alloc_message (TLS);
    bl_do_msg_set_outbound (TLS, ML[i]->id);    
  }
  int n;
  assert (fetch_int () == CODE_vector);
  n = fetch_int ();
  for (i = 0; i < n; i++) {
    tglf_fetch_alloc_chat (TLS);
  }
  assert (fetch_int () == CODE_vector);
  n = fetch_int ();
  for (i = 0; i < n; i++) {
    tglf_fetch_alloc_user (TLS);
  }
  if (op == CODE_messages_stated_messages_links) {
    assert (skip_type_any (TYPE_TO_PARAM_1 (vector, TYPE_TO_PARAM (contacts_link))) >= 0);
  }
  int pts = fetch_int ();
  int seq = fetch_int ();
  
  if (seq == TLS->seq + 1 && !(TLS->locks & TGL_LOCK_DIFF)) {
    bl_do_set_pts (TLS, pts);
    bl_do_set_seq (TLS, seq);
    int i;
    for (i = 0; i < num; i++) {
      bl_do_msg_update (TLS, ML[i]->id);
    }
  } else {
    if (seq > TLS->seq + 1) {
      vlogprintf (E_NOTICE, "Hole in seq\n");
      tgl_do_get_difference (TLS, 0, 0, 0);
    }
  }

  if (q->callback) {
    ((void (*)(struct tgl_state *, void *, int, int, struct tgl_message **))q->callback)(TLS, q->callback_extra, 1, num, ML);
  }
  tfree (ML, num * sizeof (void *));

  return 0;
}

static struct query_methods send_broadcast_methods = {
  .on_answer = send_broadcast_on_answer,
  .on_error = q_list_on_error,
  .type = TYPE_TO_PARAM(messages_stated_messages)
};

void tgl_do_send_broadcast (struct tgl_state *TLS, int num, tgl_peer_id_t id[], const char *text, int text_len, void (*callback)(struct tgl_state *TLS, void *extra, int success, int num, struct tgl_message *ML[]), void *callback_extra) {
  clear_packet ();
  out_int (CODE_messages_send_broadcast);
  out_int (CODE_vector);
  out_int (num);
  int i;
  for (i = 0; i < num; i++) {
    assert (tgl_get_peer_type (id[i]) == TGL_PEER_USER);
   
    struct tgl_user *U = (void *)tgl_peer_get (TLS, id[i]);
    if (U && U->access_hash) {
      out_int (CODE_input_user_foreign);
      out_int (tgl_get_peer_id (id[i]));
      out_long (U->access_hash);
    } else {
      out_int (CODE_input_user_contact);
      out_int (tgl_get_peer_id (id[i]));
    }
  }
  out_cstring (text, text_len);
  out_int (CODE_input_media_empty);
  tglq_send_query (TLS, TLS->DC_working, packet_ptr - packet_buffer, packet_buffer, &send_broadcast_methods, 0, callback, callback_extra);
}

static void set_flag_4 (struct tgl_state *TLS, void *_D, int success) {
  struct tgl_dc *D = _D;
  assert (success);
  D->flags |= 4;

  TLS->timer_methods->insert (D->ev, TLS->temp_key_expire_time * 0.9);
}

static int send_bind_temp_on_answer (struct tgl_state *TLS, struct query *q) {
  assert (fetch_int () == (int)CODE_bool_true);
  struct tgl_dc *DC = q->extra;
  DC->flags |= 2;
  tgl_do_help_get_config_dc (TLS, DC, set_flag_4, DC);
  vlogprintf (E_DEBUG, "Bind successful in dc %d\n", DC->id);
  return 0;
}

static int send_bind_on_error (struct tgl_state *TLS, struct query *q, int error_code, int l, const char *error) {
  vlogprintf (E_WARNING, "bind: error %d: %.*s\n", error_code, l, error);
  if (error_code == 400) {
    return -11;
  }
  return 0;
}

static struct query_methods send_bind_temp_methods = {
  .on_answer = send_bind_temp_on_answer,
  .on_error = send_bind_on_error,
  .type = TYPE_TO_PARAM (bool)
};

void tgl_do_send_bind_temp_key (struct tgl_state *TLS, struct tgl_dc *D, long long nonce, int expires_at, void *data, int len, long long msg_id) {
  clear_packet ();
  out_int (CODE_auth_bind_temp_auth_key);
  out_long (D->auth_key_id);
  out_long (nonce);
  out_int (expires_at);
  out_cstring (data, len);
  struct query *q = tglq_send_query_ex (TLS, D, packet_ptr - packet_buffer, packet_buffer, &send_bind_temp_methods, D, 0, 0, 2);
  assert (q->msg_id == msg_id);
}

static int update_status_on_answer (struct tgl_state *TLS, struct query *q) {
  fetch_bool ();
  
  if (q->callback) {
    ((void (*)(struct tgl_state *, void *, int))q->callback) (TLS, q->callback_extra, 1);
  }
  return 0;
}

static struct query_methods update_status_methods = {
  .on_answer = update_status_on_answer,
  .on_error = q_void_on_error,
  .type = TYPE_TO_PARAM(bool)
};

void tgl_do_update_status (struct tgl_state *TLS, int online, void (*callback)(struct tgl_state *TLS, void *callback_extra, int success), void *callback_extra) {
  clear_packet ();
  out_int (CODE_account_update_status);
  out_int (online ? CODE_bool_false : CODE_bool_true);
  tglq_send_query (TLS, TLS->DC_working, packet_ptr - packet_buffer, packet_buffer, &update_status_methods, 0, callback, callback_extra);
}


void tgl_do_request_exchange (struct tgl_state *TLS, struct tgl_secret_chat *E) {
  static unsigned char s[256];
  tglt_secure_random (s, 256);

  long long id;
  tglt_secure_random (&id, 8);

  bl_do_encr_chat_exchange_request (TLS, E, id, s);
  
  BIGNUM *a = BN_bin2bn (s, 256, 0);
  ensure_ptr (a);
  BIGNUM *p = BN_bin2bn (TLS->encr_prime, 256, 0); 
  ensure_ptr (p);
 
  BIGNUM *g = BN_new ();
  ensure_ptr (g);

  ensure (BN_set_word (g, TLS->encr_root));

  BIGNUM *r = BN_new ();
  ensure_ptr (r);

  ensure (BN_mod_exp (r, g, a, p, TLS->BN_ctx));
  
  static unsigned char kk[256];
  memset (kk, 0, sizeof (kk));
  BN_bn2bin (r, kk + (256 - BN_num_bytes (r)));

  BN_clear_free (a);
  BN_clear_free (g);
  BN_clear_free (p);
  BN_clear_free (r);
  
  static int action[70];  
  action[0] = CODE_decrypted_message_action_request_key;
  *(long long *)(action + 1) = E->exchange_id;
  action[3] = 0x100fe;
  memcpy (action + 4, kk, 256);

  long long t;
  tglt_secure_random (&t, 8);

  bl_do_send_message_action_encr (TLS, t, TLS->our_id, tgl_get_peer_type (E->id), tgl_get_peer_id (E->id), time (0), 68, action);
  
  struct tgl_message *M = tgl_message_get (TLS, t);
  assert (M);
  assert (M->action.type == tgl_message_action_request_key);
  tgl_do_send_msg (TLS, M, 0, 0);
}

void tgl_do_accept_exchange (struct tgl_state *TLS, struct tgl_secret_chat *E, long long exchange_id, unsigned char ga[]) {
  static unsigned char s[256];
  tglt_secure_random (s, 256);

  BIGNUM *b = BN_bin2bn (s, 256, 0);
  ensure_ptr (b);
  BIGNUM *g_a = BN_bin2bn (ga, 256, 0);
  ensure_ptr (g_a);

  assert (tglmp_check_g_a (TLS, TLS->encr_prime_bn, g_a) >= 0);
  //if (!ctx) {
  //  ctx = BN_CTX_new ();
  //  ensure_ptr (ctx);
  //}
  BIGNUM *p = TLS->encr_prime_bn; 
  ensure_ptr (p);
  BIGNUM *r = BN_new ();
  ensure_ptr (r);
  ensure (BN_mod_exp (r, g_a, b, p, TLS->BN_ctx));

  static unsigned char kk[256];
  memset (kk, 0, sizeof (kk));
  BN_bn2bin (r, kk + (256 - BN_num_bytes (r)));

  bl_do_encr_chat_exchange_accept (TLS, E, exchange_id, kk);
  
  ensure (BN_set_word (g_a, TLS->encr_root));
  ensure (BN_mod_exp (r, g_a, b, p, TLS->BN_ctx));
  
  static unsigned char buf[256];
  memset (buf, 0, sizeof (buf));
  BN_bn2bin (r, buf + (256 - BN_num_bytes (r)));
  
  static int action[70];  
  action[0] = CODE_decrypted_message_action_accept_key;
  *(long long *)(action + 1) = E->exchange_id;
  action[3] = 0x100fe;
  memcpy (action + 4, buf, 256);
  *(long long *)(action + 68) = E->exchange_key_fingerprint;

  long long t;
  tglt_secure_random (&t, 8);

  bl_do_send_message_action_encr (TLS, t, TLS->our_id, tgl_get_peer_type (E->id), tgl_get_peer_id (E->id), time (0), 70, action);

  BN_clear_free (b);
  BN_clear_free (g_a);
  BN_clear_free (r);
  
  struct tgl_message *M = tgl_message_get (TLS, t);
  assert (M);
  assert (M->action.type == tgl_message_action_accept_key);
  tgl_do_send_msg (TLS, M, 0, 0);
}
  
void tgl_do_confirm_exchange (struct tgl_state *TLS, struct tgl_secret_chat *E, int sen_nop) {
  bl_do_encr_chat_exchange_confirm (TLS, E);
  if (sen_nop) {
    int action = CODE_decrypted_message_action_noop;
  
    long long t;
    tglt_secure_random (&t, 8);

    bl_do_send_message_action_encr (TLS, t, TLS->our_id, tgl_get_peer_type (E->id), tgl_get_peer_id (E->id), time (0), 1, &action);

    struct tgl_message *M = tgl_message_get (TLS, t);
    assert (M);
    assert (M->action.type == tgl_message_action_noop);
    tgl_do_send_msg (TLS, M, 0, 0);
  }
}

void tgl_do_commit_exchange (struct tgl_state *TLS, struct tgl_secret_chat *E, unsigned char gb[]) {
  assert (TLS->encr_prime);
  
  BIGNUM *g_b = BN_bin2bn (gb, 256, 0);  
  ensure_ptr (g_b);
  assert (tglmp_check_g_a (TLS, TLS->encr_prime_bn, g_b) >= 0);

  BIGNUM *p = TLS->encr_prime_bn;
  ensure_ptr (p);
  BIGNUM *r = BN_new ();
  ensure_ptr (r);
  BIGNUM *a = BN_bin2bn ((void *)E->exchange_key, 256, 0);
  ensure_ptr (a);
  ensure (BN_mod_exp (r, g_b, a, p, TLS->BN_ctx));

  static unsigned char s[256];
  memset (s, 0, 256);
  
  BN_bn2bin (r, s + (256 - BN_num_bytes (r)));
  
  BN_clear_free (g_b);
  BN_clear_free (r);
  BN_clear_free (a);
 
  static unsigned char sh[20];
  SHA1 (s, 256, sh);
  
  int action[4];
  action[0] = CODE_decrypted_message_action_commit_key;
  *(long long *)(action + 1) = E->exchange_id;
  *(long long *)(action + 3) = *(long long *)(sh + 12);
  
  long long t;
  tglt_secure_random (&t, 8);

  bl_do_send_message_action_encr (TLS, t, TLS->our_id, tgl_get_peer_type (E->id), tgl_get_peer_id (E->id), time (0), 5, action);
  
  struct tgl_message *M = tgl_message_get (TLS, t);
  assert (M);
  assert (M->action.type == tgl_message_action_commit_key);
  tgl_do_send_msg (TLS, M, 0, 0);
  
  bl_do_encr_chat_exchange_commit (TLS, E, s);
}

void tgl_do_abort_exchange (struct tgl_state *TLS, struct tgl_secret_chat *E) {
  bl_do_encr_chat_exchange_abort (TLS, E);
}

void tgl_started_cb (struct tgl_state *TLS, void *arg, int success) {
  assert (success);
  TLS->started = 1;
  if (TLS->callback.started) {
    TLS->callback.started (TLS);
  }
}

void tgl_export_auth_callback (struct tgl_state *TLS, void *arg, int success) {
  assert (success);
  int i;
  for (i = 0; i <= TLS->max_dc_num; i++) if (TLS->DC_list[i] && !tgl_signed_dc (TLS, TLS->DC_list[i])) {
    return; 
  }
  if (TLS->callback.logged_in) {
    TLS->callback.logged_in (TLS);
  }
  
  tglm_send_all_unsent (TLS);
  tgl_do_get_difference (TLS, 0, tgl_started_cb, 0);
}

void tgl_export_all_auth (struct tgl_state *TLS) {
  int i;
  int ok = 1;
  for (i = 0; i <= TLS->max_dc_num; i++) if (TLS->DC_list[i] && !tgl_signed_dc (TLS, TLS->DC_list[i])) {
    tgl_do_export_auth (TLS, i, tgl_export_auth_callback, (void*)(long)TLS->DC_list[i]);   
    ok = 0;
  }
  if (ok) {
    if (TLS->callback.logged_in) {
      TLS->callback.logged_in (TLS);
    }

    tglm_send_all_unsent (TLS);
    tgl_do_get_difference (TLS, 0, tgl_started_cb, 0);
  }
}

void tgl_sign_in_code (struct tgl_state *TLS, const char *code, void *_T);
void tgl_sign_in_result (struct tgl_state *TLS, void *_T, int success, struct tgl_user *U) {
  void **T = _T;
  if (success) {
    tfree_str (T[0]);
    tfree_str (T[1]);
    tfree (T, sizeof (void *) * 4);
  } else {
    vlogprintf (E_ERROR, "incorrect code\n");
    TLS->callback.get_string (TLS, "code ('call' for phone call):", 0, tgl_sign_in_code, T);
    return;
  }
  tgl_export_all_auth (TLS);
}

void tgl_sign_in_code (struct tgl_state *TLS, const char *code, void *_T) {
  void **T = _T;
  if (!strcmp (code, "call")) {
    tgl_do_phone_call (TLS, T[0], T[1], 0, 0);
    TLS->callback.get_string (TLS, "code ('call' for phone call):", 0, tgl_sign_in_code, T);
    return;
  }
  
  tgl_do_send_code_result (TLS, T[0], T[1], code, tgl_sign_in_result, T);
}

void tgl_sign_up_code (struct tgl_state *TLS, const char *code, void *_T);
void tgl_sign_up_result (struct tgl_state *TLS, void *_T, int success, struct tgl_user *U) {
  void **T = _T;
  if (success) {
    tfree_str (T[0]);
    tfree_str (T[1]);
    tfree_str (T[2]);
    tfree_str (T[3]);
    tfree (T, sizeof (void *) * 4);
  } else {
    vlogprintf (E_ERROR, "incorrect code\n");
    TLS->callback.get_string (TLS, "code ('call' for phone call):", 0, tgl_sign_up_code, T);
    return;
  }
  tgl_export_all_auth (TLS);
}

void tgl_sign_up_code (struct tgl_state *TLS, const char *code, void *_T) {
  void **T = _T;
  if (!strcmp (code, "call")) {
    tgl_do_phone_call (TLS, T[0], T[1], 0, 0);
    TLS->callback.get_string (TLS, "code ('call' for phone call):", 0, tgl_sign_up_code, T);
    return;
  }
  
  tgl_do_send_code_result_auth (TLS, T[0], T[1], code, T[2], T[3], tgl_sign_up_result, T);
}


void tgl_last_name_cb (struct tgl_state *TLS, const char *last_name, void *_T) {
  void **T = _T;
  T[3] = tstrdup (last_name);
  TLS->callback.get_string (TLS, "code ('call' for phone call):", 0, tgl_sign_up_code, T);
}

void tgl_first_name_cb (struct tgl_state *TLS, const char *first_name, void *_T) {
  void **T = _T;
  if (strlen (first_name) < 1) {
    TLS->callback.get_string (TLS, "First name:", 0, tgl_first_name_cb, T);
    return;
  }
  T[2] = tstrdup (first_name);
  TLS->callback.get_string (TLS, "Last name:", 0, tgl_last_name_cb, T);
}

void tgl_register_cb (struct tgl_state *TLS, const char *yn, void *_T) {
  void **T = _T;
  if (strlen (yn) > 1) {
    TLS->callback.get_string (TLS, "register [Y/n]:", 0, tgl_register_cb, _T);
  } else if (strlen (yn) == 0 || *yn == 'y' || *yn == 'Y') {
    TLS->callback.get_string (TLS, "First name:", 0, tgl_first_name_cb, _T);
  } else if (*yn == 'n' || *yn == 'N') {
    vlogprintf (E_ERROR, "stopping registration");
    tfree_str (T[0]);
    tfree_str (T[1]);
    tfree (T, sizeof (void *) * 4);
    tgl_login (TLS);
  } else {
    TLS->callback.get_string (TLS, "register [Y/n]:", 0, tgl_register_cb, _T);
  }
}

void tgl_sign_in_phone (struct tgl_state *TLS, const char *phone, void *arg);
void tgl_sign_in_phone_cb (struct tgl_state *TLS, void *extra, int success, int registered, const char *mhash) {
  void **T = extra;
  if (!success) {
    vlogprintf (E_ERROR, "Incorrect phone number\n");
    tfree_str (T[0]);
    tfree (T, sizeof (void *) * 4);
    TLS->callback.get_string (TLS, "phone number:", 0, tgl_sign_in_phone, NULL);
    return;
  }
  T[1] = tstrdup (mhash);
  if (registered) {
    TLS->callback.get_string (TLS, "code ('call' for phone call):", 0, tgl_sign_in_code, T);
  } else {
    TLS->callback.get_string (TLS, "register [Y/n]:", 0, tgl_register_cb, T);
  }
}

void tgl_sign_in_phone (struct tgl_state *TLS, const char *phone, void *arg) {
  void **T = talloc0 (sizeof (void *) * 4);
  T[0] = tstrdup (phone);
  tgl_do_send_code (TLS, phone, tgl_sign_in_phone_cb, T);
}

void tgl_sign_in (struct tgl_state *TLS) {
  if (!tgl_signed_dc (TLS, TLS->DC_working)) {
    TLS->callback.get_string (TLS, "phone number:", 0, tgl_sign_in_phone, NULL);
  } else {
    tgl_export_all_auth (TLS);
  }
}

static void check_authorized (struct tgl_state *TLS, void *arg) {
  int i;
  int ok = 1;
  for (i = 0; i <= TLS->max_dc_num; i++) {
    if (TLS->DC_list[i] && !tgl_authorized_dc (TLS, TLS->DC_list[i])) {
      ok = 0;
      break;
    }
  }

  if (ok) {
    TLS->timer_methods->free (TLS->ev_login);
    TLS->ev_login = NULL;
    tgl_sign_in (TLS);
  } else {
    TLS->timer_methods->insert (TLS->ev_login, 0.1);
  }
}

void tgl_login (struct tgl_state *TLS) {
  int i;
  int ok = 1;
  for (i = 0; i <= TLS->max_dc_num; i++) {
    if (TLS->DC_list[i] && !tgl_authorized_dc (TLS, TLS->DC_list[i])) {
      ok = 0;
      break;
    }
  }
  
  if (!ok) {
    TLS->ev_login = TLS->timer_methods->alloc (TLS, check_authorized, NULL);
    TLS->timer_methods->insert (TLS->ev_login, 0.1);
  } else {
    tgl_sign_in (TLS);
  }
}
