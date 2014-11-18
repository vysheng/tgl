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

#ifndef __TGL_SERIALIZE_H__
#define __TGL_SERIALIZE_H__

struct tgl_serialize_callback {
    const char *(*get_auth_key_filename) (void);
    const char *(*get_state_filename) (void);
    const char *(*get_secret_chat_filename) (void);
};

extern struct tgl_serialize_methods tgl_file_methods;
extern struct tgl_serialize_callback tgl_file_config;

#endif /* defined(__TGL_SERIALIZE_H__) */
