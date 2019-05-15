/*
 * mem.h - This file is part of libm10k
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

#ifndef _M10K_MEM_H
#define _M10K_MEM_H

#include <m10k/types.h>

int m10k_mem_alloc(void**, m10k_size);
int m10k_mem_free(void**);

int m10k_mem_ref(void**);
int m10k_mem_unref(void**);

#define m10k_salloc(p) m10k_mem_alloc((void**)&(p), sizeof(*(p)))
#define m10k_ref(p)    m10k_mem_ref((void**)&(p))
#define m10k_unref(p)  m10k_mem_unref((void**)&(p))

#endif /* _M10K_MEM_H */
