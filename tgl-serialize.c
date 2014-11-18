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

    Copyright Vitaly Valtman 2013-2014
    Copyright Paul Eipper 2014
*/

#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>

#include "tgl-serialize.h"
#include "tgl-binlog.h"
#include "tgl-inner.h"
#include "tgl-structures.h"
#include "tgl.h"

#define DC_SERIALIZED_MAGIC 0x868aa81d
#define STATE_FILE_MAGIC 0x28949a93
#define SECRET_CHAT_FILE_MAGIC 0x37a1988a


int read_state_file (struct tgl_state *TLS) {
    int state_file_fd = open (tgl_file_config.get_state_filename (), O_CREAT | O_RDWR, 0600);
    if (state_file_fd < 0) {
        return -1;
    }
    int version, magic;
    if (read (state_file_fd, &magic, 4) < 4) { close (state_file_fd); return -1; }
    if (magic != (int)STATE_FILE_MAGIC) { close (state_file_fd); return -1; }
    if (read (state_file_fd, &version, 4) < 4) { close (state_file_fd); return -1; }
    assert (version >= 0);
    int x[4];
    if (read (state_file_fd, x, 16) < 16) {
        close (state_file_fd);
        return -1;
    }
    int pts = x[0];
    int qts = x[1];
    int seq = x[2];
    int date = x[3];
    close (state_file_fd);
    bl_do_set_seq (TLS, seq);
    bl_do_set_pts (TLS, pts);
    bl_do_set_qts (TLS, qts);
    bl_do_set_date (TLS, date);
    return 0;
}

int write_state_file (struct tgl_state *TLS) {
    static int wseq;
    static int wpts;
    static int wqts;
    static int wdate;
    if (wseq >= TLS->seq && wpts >= TLS->pts && wqts >= TLS->qts && wdate >= TLS->date) { return -1; }
    wseq = TLS->seq; wpts = TLS->pts; wqts = TLS->qts; wdate = TLS->date;
    int state_file_fd = open (tgl_file_config.get_state_filename (), O_CREAT | O_RDWR, 0600);
    if (state_file_fd < 0) {
        vlogprintf (E_ERROR, "Can not write state file '%s': %m\n", tgl_file_config.get_state_filename ());
        return -1;
    }
    int x[6];
    x[0] = STATE_FILE_MAGIC;
    x[1] = 0;
    x[2] = wpts;
    x[3] = wqts;
    x[4] = wseq;
    x[5] = wdate;
    assert (write (state_file_fd, x, 24) == 24);
    close (state_file_fd);
    return 0;
}

void write_dc (struct tgl_dc *DC, void *extra) {
    int auth_file_fd = *(int *)extra;
    if (!DC) {
        int x = 0;
        assert (write (auth_file_fd, &x, 4) == 4);
        return;
    } else {
        int x = 1;
        assert (write (auth_file_fd, &x, 4) == 4);
    }
    
    assert (DC->has_auth);
    
    assert (write (auth_file_fd, &DC->port, 4) == 4);
    int l = (int)(strlen (DC->ip));
    assert (write (auth_file_fd, &l, 4) == 4);
    assert (write (auth_file_fd, DC->ip, l) == l);
    assert (write (auth_file_fd, &DC->auth_key_id, 8) == 8);
    assert (write (auth_file_fd, DC->auth_key, 256) == 256);
}

int write_auth_file (struct tgl_state *TLS) {
    int auth_file_fd = open (tgl_file_config.get_auth_key_filename (), O_CREAT | O_RDWR, 0600);
    assert (auth_file_fd >= 0);
    int x = DC_SERIALIZED_MAGIC;
    assert (write (auth_file_fd, &x, 4) == 4);
    assert (write (auth_file_fd, &TLS->max_dc_num, 4) == 4);
    assert (write (auth_file_fd, &TLS->dc_working_num, 4) == 4);
    
    tgl_dc_iterator_ex (TLS, write_dc, &auth_file_fd);
    
    assert (write (auth_file_fd, &TLS->our_id, 4) == 4);
    close (auth_file_fd);
    return 0;
}

void write_secret_chat (tgl_peer_t *_P, void *extra) {
    struct tgl_secret_chat *P = (void *)_P;
    if (tgl_get_peer_type (P->id) != TGL_PEER_ENCR_CHAT) { return; }
    if (P->state != sc_ok) { return; }
    int *a = extra;
    int fd = a[0];
    a[1] ++;
    
    int id = tgl_get_peer_id (P->id);
    assert (write (fd, &id, 4) == 4);
    //assert (write (fd, &P->flags, 4) == 4);
    int l = (int)(strlen (P->print_name));
    assert (write (fd, &l, 4) == 4);
    assert (write (fd, P->print_name, l) == l);
    assert (write (fd, &P->user_id, 4) == 4);
    assert (write (fd, &P->admin_id, 4) == 4);
    assert (write (fd, &P->date, 4) == 4);
    assert (write (fd, &P->ttl, 4) == 4);
    assert (write (fd, &P->layer, 4) == 4);
    assert (write (fd, &P->access_hash, 8) == 8);
    assert (write (fd, &P->state, 4) == 4);
    assert (write (fd, &P->key_fingerprint, 8) == 8);
    assert (write (fd, &P->key, 256) == 256);
    assert (write (fd, &P->in_seq_no, 4) == 4);
    assert (write (fd, &P->last_in_seq_no, 4) == 4);
    assert (write (fd, &P->out_seq_no, 4) == 4);
}

int write_secret_chat_file (struct tgl_state *TLS) {
    int secret_chat_fd = open (tgl_file_config.get_secret_chat_filename (), O_CREAT | O_RDWR, 0600);
    assert (secret_chat_fd >= 0);
    int x = SECRET_CHAT_FILE_MAGIC;
    assert (write (secret_chat_fd, &x, 4) == 4);
    x = 1;
    assert (write (secret_chat_fd, &x, 4) == 4); // version
    assert (write (secret_chat_fd, &x, 4) == 4); // num
    
    int y[2];
    y[0] = secret_chat_fd;
    y[1] = 0;
    
    tgl_peer_iterator_ex (TLS, write_secret_chat, y);
    
    lseek (secret_chat_fd, 8, SEEK_SET);
    assert (write (secret_chat_fd, &y[1], 4) == 4);
    close (secret_chat_fd);
    return 0;
}

void read_dc (struct tgl_state *TLS, int auth_file_fd, int id, unsigned ver) {
    int port = 0;
    assert (read (auth_file_fd, &port, 4) == 4);
    int l = 0;
    assert (read (auth_file_fd, &l, 4) == 4);
    assert (l >= 0 && l < 100);
    char ip[100];
    assert (read (auth_file_fd, ip, l) == l);
    ip[l] = 0;
    
    long long auth_key_id;
    static unsigned char auth_key[256];
    assert (read (auth_file_fd, &auth_key_id, 8) == 8);
    assert (read (auth_file_fd, auth_key, 256) == 256);
    
    //bl_do_add_dc (id, ip, l, port, auth_key_id, auth_key);
    bl_do_dc_option (TLS, id, 2, "DC", l, ip, port);
    bl_do_set_auth_key_id (TLS, id, auth_key);
    bl_do_dc_signed (TLS, id);
}

void empty_auth_file (struct tgl_state *TLS) {
    if (TLS->test_mode) {
        bl_do_dc_option (TLS, 1, 0, "", strlen (TG_SERVER_TEST_1), TG_SERVER_TEST_1, 443);
        bl_do_dc_option (TLS, 2, 0, "", strlen (TG_SERVER_TEST_2), TG_SERVER_TEST_2, 443);
        bl_do_dc_option (TLS, 3, 0, "", strlen (TG_SERVER_TEST_3), TG_SERVER_TEST_3, 443);
        bl_do_set_working_dc (TLS, 2);
    } else {
        bl_do_dc_option (TLS, 1, 0, "", strlen (TG_SERVER_1), TG_SERVER_1, 443);
        bl_do_dc_option (TLS, 2, 0, "", strlen (TG_SERVER_2), TG_SERVER_2, 443);
        bl_do_dc_option (TLS, 3, 0, "", strlen (TG_SERVER_3), TG_SERVER_3, 443);
        bl_do_dc_option (TLS, 4, 0, "", strlen (TG_SERVER_4), TG_SERVER_4, 443);
        bl_do_dc_option (TLS, 5, 0, "", strlen (TG_SERVER_5), TG_SERVER_5, 443);
        bl_do_set_working_dc (TLS, 4);
    }
}

int read_auth_file (struct tgl_state *TLS) {
    int auth_file_fd = open (tgl_file_config.get_auth_key_filename (), O_CREAT | O_RDWR, 0600);
    if (auth_file_fd < 0) {
        empty_auth_file (TLS);
        return 0;
    }
    assert (auth_file_fd >= 0);
    unsigned x;
    unsigned m;
    if (read (auth_file_fd, &m, 4) < 4 || (m != DC_SERIALIZED_MAGIC)) {
        close (auth_file_fd);
        empty_auth_file (TLS);
        return 0;
    }
    assert (read (auth_file_fd, &x, 4) == 4);
    assert (x > 0);
    int dc_working_num;
    assert (read (auth_file_fd, &dc_working_num, 4) == 4);
    
    int i;
    for (i = 0; i <= (int)x; i++) {
        int y;
        assert (read (auth_file_fd, &y, 4) == 4);
        if (y) {
            read_dc (TLS, auth_file_fd, i, m);
        }
    }
    bl_do_set_working_dc (TLS, dc_working_num);
    int our_id;
    int l = (int)(read (auth_file_fd, &our_id, 4));
    if (l < 4) {
        assert (!l);
    }
    if (our_id) {
        bl_do_set_our_id (TLS, our_id);
    }
    close (auth_file_fd);
    return 0;
}

void read_secret_chat (struct tgl_state *TLS, int fd, int v) {
    int id, l, user_id, admin_id, date, ttl, layer, state;
    long long access_hash, key_fingerprint;
    static char s[1000];
    static unsigned char key[256];
    assert (read (fd, &id, 4) == 4);
    //assert (read (fd, &flags, 4) == 4);
    assert (read (fd, &l, 4) == 4);
    assert (l > 0 && l < 1000);
    assert (read (fd, s, l) == l);
    assert (read (fd, &user_id, 4) == 4);
    assert (read (fd, &admin_id, 4) == 4);
    assert (read (fd, &date, 4) == 4);
    assert (read (fd, &ttl, 4) == 4);
    assert (read (fd, &layer, 4) == 4);
    assert (read (fd, &access_hash, 8) == 8);
    assert (read (fd, &state, 4) == 4);
    assert (read (fd, &key_fingerprint, 8) == 8);
    assert (read (fd, &key, 256) == 256);
    int in_seq_no = 0, out_seq_no = 0, last_in_seq_no = 0;
    if (v >= 1) {
        assert (read (fd, &in_seq_no, 4) == 4);
        assert (read (fd, &last_in_seq_no, 4) == 4);
        assert (read (fd, &out_seq_no, 4) == 4);
    }
    
    bl_do_encr_chat_create (TLS, id, user_id, admin_id, s, l);
    struct tgl_secret_chat  *P = (void *)tgl_peer_get (TLS, TGL_MK_ENCR_CHAT (id));
    assert (P && (P->flags & FLAG_CREATED));
    bl_do_encr_chat_set_date (TLS, P, date);
    bl_do_encr_chat_set_ttl (TLS, P, ttl);
    bl_do_encr_chat_set_layer (TLS, P, layer);
    bl_do_encr_chat_set_access_hash (TLS, P, access_hash);
    bl_do_encr_chat_set_state (TLS, P, state);
    bl_do_encr_chat_set_key (TLS, P, key, key_fingerprint);
    if (v >= 1) {
        bl_do_encr_chat_set_seq (TLS, P, in_seq_no, last_in_seq_no, out_seq_no);
    }
}

int read_secret_chat_file (struct tgl_state *TLS) {
    int secret_chat_fd = open (tgl_file_config.get_secret_chat_filename (), O_RDWR, 0600);
    if (secret_chat_fd < 0) { return -1; }
    //assert (secret_chat_fd >= 0);
    int x;
    if (read (secret_chat_fd, &x, 4) < 4) { close (secret_chat_fd); return -1; }
    if (x != SECRET_CHAT_FILE_MAGIC) { close (secret_chat_fd); return -1; }
    int v = 0;
    assert (read (secret_chat_fd, &v, 4) == 4);
    assert (v == 0 || v == 1); // version
    assert (read (secret_chat_fd, &x, 4) == 4);
    assert (x >= 0);
    while (x --> 0) {
        read_secret_chat (TLS, secret_chat_fd, v);
    }
    close (secret_chat_fd);
    return 0;
}

struct tgl_serialize_methods tgl_file_methods = {
    .load_auth = read_auth_file,
    .load_state = read_state_file,
    .load_secret_chats = read_secret_chat_file,
    .store_auth = write_auth_file,
    .store_state = write_state_file,
    .store_secret_chats = write_secret_chat_file,
};
