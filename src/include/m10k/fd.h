/*
 * fd.h - This file is part of libm10k
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

#ifndef _M10K_FD_H
#define _M10K_FD_H

#include <stdlib.h>

typedef struct _m10k_fd m10k_fd;

typedef enum {
	M10K_FD_EVENT_IN = 0,
	M10K_FD_EVENT_OUT,
	M10K_FD_EVENT_ERR,
	M10K_FD_EVENT_HUP,
	M10K_FD_EVENT_NUM
} m10k_fd_event;

typedef enum {
	M10K_FD_DOM_UNIX = 0,
	M10K_FD_DOM_NUM
} m10k_fd_dom;

typedef enum {
	M10K_FD_TYPE_SERVER = 0,
	M10K_FD_TYPE_CLIENT
} m10k_fd_type;

#define m10k_fd_dom_valid(dom)   ((dom) >= 0 && (dom) < M10K_FD_DOM_NUM)
#define m10k_fd_type_valid(type) ((type) == M10K_FD_TYPE_SERVER		\
								  || (type) == M10K_FD_TYPE_CLIENT)

typedef void (m10k_fd_func)(m10k_fd*, m10k_fd_event, void*, void*);

int     m10k_fd_new(m10k_fd**, m10k_fd_dom, ...);
int     m10k_fd_free(m10k_fd**);

int     m10k_fd_close(m10k_fd*);
ssize_t m10k_fd_read(m10k_fd*, void*, const size_t);
ssize_t m10k_fd_write(m10k_fd*, const void*, const size_t);
int     m10k_fd_accept(m10k_fd*, m10k_fd**);

int     m10k_fd_set_callback(m10k_fd*, m10k_fd_event, m10k_fd_func*, void*);
int     m10k_fd_notify(m10k_fd*, m10k_fd_event, void*);

#endif /* _M10K_FD_H */
