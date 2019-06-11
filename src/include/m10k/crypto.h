/*
 * crypto.h - This file is part of libm10k
 * Copyright (C) 2019 Matthias Kruk
 *
 * libm10k is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 3, or (at your
 * option) any later version.
 *
 * libm10k is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libxhome; see the file COPYING.  If not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#ifndef _M10K_CRYPTO_H
#define _M10K_CRYPTO_H

#include <stdlib.h>

typedef struct _m10k_key m10k_key;

int m10k_key_new(m10k_key**, int);
int m10k_key_new_from_file(m10k_key**, const char*);

int m10k_key_to_file(m10k_key*, const char*);
int m10k_key_to_der(m10k_key*, void*, size_t);
int m10k_key_sign(m10k_key*, const void*, const size_t, void*, const size_t);
int m10k_key_verify(m10k_key*, const void*, const size_t, const void*, const size_t);

void m10k_key_free(m10k_key**);

typedef struct _m10k_cert m10k_cert;

int m10k_cert_new(m10k_cert**, m10k_key*, int, const char*, const char*, const char*);
int m10k_cert_new_from_file(m10k_cert**, const char*);
int m10k_cert_new_from_der(m10k_cert**, const void*, const size_t);
int m10k_cert_set_expiration(m10k_cert*, int);
int m10k_cert_get_name(m10k_cert*, char*, const size_t);
int m10k_cert_get_public_key(m10k_cert*, m10k_key**);

int m10k_cert_to_file(m10k_cert*, const char*);
int m10k_cert_to_der(m10k_cert*, void*, const size_t);

void m10k_cert_free(m10k_cert**);

typedef struct _m10k_cert_req m10k_cert_req;

int m10k_cert_req_new(m10k_cert_req**, m10k_key*, const char*, const char*, const char*);
int m10k_cert_req_new_from_der(m10k_cert_req**, const void*, const size_t);
int m10k_cert_req_new_from_file(m10k_cert_req**, const char*);

int m10k_cert_req_to_der(m10k_cert_req*, void*, const size_t);
int m10k_cert_req_to_file(m10k_cert_req*, const char*);
int m10k_cert_req_sign(m10k_cert_req*, m10k_cert*, m10k_key*, m10k_cert**);

void m10k_cert_req_free(m10k_cert_req**);

#endif /* _M10K_CRYPTO_H */
