/*
 * dispatcher.h - This file is part of libm10k
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

#ifndef _M10K_DISPATCHER_H
#define _M10K_DISPATCHER_H

#include <m10k/fd.h>

typedef struct _m10k_dispatcher m10k_dispatcher;

typedef enum {
	M10K_DISPATCHER_FLAG_THREADED = (1 << 0),
	M10K_DISPATCHER_FLAG_RUNNING  = (1 << 8),
	M10K_DISPATCHER_FLAG_STOP     = (1 << 9),
	M10K_DISPATCHER_FLAG_INVALID  = (1 << 30)
} m10k_dispatcher_flags;

int m10k_dispatcher_new(m10k_dispatcher**);
int m10k_dispatcher_free(m10k_dispatcher**);

int m10k_dispatcher_add_fd(m10k_dispatcher*, m10k_fd*);
int m10k_dispatcher_drop_fd(m10k_dispatcher*, m10k_fd*);

int m10k_dispatcher_set_flags(m10k_dispatcher*,
							  m10k_dispatcher_flags,
							  m10k_dispatcher_flags);
int m10k_dispatcher_get_flags(m10k_dispatcher*,
							  m10k_dispatcher_flags*);

int m10k_dispatcher_run(m10k_dispatcher*);

#endif /* _M10K_DISPATCHER_H */
