/*
 * list.h - This file is part of libm10k
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

#ifndef _M10K_LIST_H
#define _M10K_LIST_H

typedef struct _m10k_list m10k_list;

int   m10k_list_new(m10k_list**);
int   m10k_list_free(m10k_list**);

int   m10k_list_prepend(m10k_list*, void*);
int   m10k_list_append(m10k_list*, void*);
int   m10k_list_remove(m10k_list*, void*);
void* m10k_list_find(m10k_list*, int(*)(void*, void*), void*);
int   m10k_list_foreach(m10k_list*, int(*)(void*, void*), void*);

#endif /* _M10K_LIST_H */
