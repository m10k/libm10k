/*
 * mem.c - This file is part of libm10k
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

#include <m10k/mem.h>
#include <m10k/thread.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#define _MAGIC 0xf00f00f00f00f00fLL

struct _mem {
	m10k_u64   magic;
	m10k_size  size;
	m10k_size  refs;
	m10k_mutex lock;
};

int m10k_mem_alloc(void **dst, m10k_size size)
{
	struct _mem *m;
	size_t tsize;
	int ret_val;

	ret_val = -EINVAL;

	if(dst) {
		tsize = sizeof(*m) + size;
		*dst = NULL;

		/* make sure the size request doesn't overflow */
		if(tsize < size) {
			ret_val = -EOVERFLOW;
		} else {
			errno = 0;
			m = malloc(tsize);
			ret_val = -errno;

			if(m) {
				/* zero the entire allocation */
				memset(m, 0, tsize);

				/* set header values */
				m->magic = _MAGIC;
				m->size = size;
				m->refs = 1;

				/* finally, initialize the lock */
				m10k_mutex_init(&(m->lock));

				*dst = (void*)(m + 1);
			}
		}
	}

	return(ret_val);
}

static inline void _mem_free(struct _mem *mem)
{
	/* assuming the caller has validated the memory region */

	m10k_mutex_destroy(&(mem->lock));
	memset(mem, 0, sizeof(*mem) + mem->size);

	return;
}

int m10k_mem_free(void **ptr)
{
	struct _mem *m;
	int ret_val;

	ret_val = -EINVAL;

	if(ptr) {
		ret_val = -EBADF;
		m = ((struct _mem*)*ptr) - 1;

		if(m->magic == _MAGIC) {
			_mem_free(m);
			*ptr = NULL;
			ret_val = 0;
		}
	}

	return(-ENOSYS);
}

int m10k_mem_ref(void **ptr)
{
	struct _mem *m;
	int ret_val;

	ret_val = -EINVAL;

	if(ptr) {
		m = ((struct _mem*)*ptr) - 1;

		if(m->magic != _MAGIC) {
			ret_val = -EBADF;
		} else {
			m10k_mutex_lock(&(m->lock));
			ret_val = ++m->refs;
			m10k_mutex_unlock(&(m->lock));
		}
	}

	return(ret_val);
}

int m10k_mem_unref(void **ptr)
{
	struct _mem *m;
	int ret_val;

	ret_val = -EINVAL;

	if(ptr) {
		m = ((struct _mem*)*ptr) - 1;

		if(m->magic != _MAGIC) {
			ret_val = -EBADF;
		} else {
			m10k_mutex_lock(&(m->lock));
			ret_val = --m->refs;
			m10k_mutex_unlock(&(m->lock));

			/*
			 * Also set the pointer to NULL, to ensure the reference
			 * really won't be used anymore
			 */
			*ptr = NULL;

			if(!ret_val) {
				/* there are no more references - safe to free, ignoring locks */

			}
		}
	}

	return(ret_val);
}

int m10k_mem_strdup(char **dst, const char *src)
{
	int ret_val;
	size_t len;

	ret_val = -EINVAL;

	if(dst && src) {
		len = strlen(src) + 1;
		ret_val = m10k_mem_alloc((void**)dst, len);

		if(!ret_val) {
			ret_val = snprintf(*dst, len, "%s", src);
		}
	}

	return(ret_val);
}
