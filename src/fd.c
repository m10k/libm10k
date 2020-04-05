/*
 * fd.c - This file is part of libm10k
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

#define _LIBM10K_SOURCE
#include <m10k/mem.h>
#include <m10k/fd.h>
#include <m10k/log.h>
#include <m10k/thread.h>
#include <unistd.h>
#include <errno.h>
#include "fd.h"

extern struct fd_dom _dom_unix;
extern struct fd_dom _dom_mcast;
extern struct fd_dom _dom_tls;

struct fd_dom *_doms[] = {
	&_dom_unix,
	&_dom_mcast,
	&_dom_tls
};

#define _LOCK(f)   m10k_mutex_lock(&((f)->lock))
#define _UNLOCK(f) m10k_mutex_unlock(&((f)->lock))

int m10k_fd_new(m10k_fd **dst, m10k_fd_dom dom, ...)
{
	int ret_val;
	m10k_fd *fd;

	ret_val = -EINVAL;

	if(dst && m10k_fd_dom_valid(dom)) {
		ret_val = m10k_salloc(fd);

		if(!ret_val) {
			va_list args;

			assert(m10k_mutex_init(&(fd->lock)) == 0);
			fd->fd = -1;

			va_start(args, dom);
			ret_val = _doms[dom]->ops->open(fd, args);
			va_end(args);

			if(ret_val < 0) {
				m10k_unref(fd);
			} else {
				fd->dom = dom;
				fd->ops = _doms[dom]->ops;
			}
		}

		*dst = fd;
	}

	return(ret_val);
}

int m10k_fd_free(m10k_fd **fd)
{
	int ret_val;

	ret_val = -EINVAL;

	if(fd && *fd) {
		ret_val = m10k_fd_close(*fd);
		m10k_mem_unref((void**)fd);
	}

	return(ret_val);
}

int m10k_fd_close(m10k_fd *fd)
{
	int ret_val;

	ret_val = -EINVAL;

	if(fd) {
		ret_val = -EBADFD;

		_LOCK(fd);

		if(fd->fd >= 0) {
			ret_val = fd->ops->close(fd);

			close(fd->fd);
			fd->fd = -1;
		}

		_UNLOCK(fd);
	}

	return(ret_val);
}

ssize_t m10k_fd_read(m10k_fd *fd, void *dst, const size_t dsize)
{
	ssize_t ret_val;

	ret_val = (ssize_t)-EINVAL;

	if(fd && dst) {
		ret_val = fd->ops->read ?
			fd->ops->read(fd, dst, dsize) : -EOPNOTSUPP;
	}

	return(ret_val);
}

ssize_t m10k_fd_write(m10k_fd *fd, const void *src, const size_t slen)
{
	ssize_t ret_val;

	ret_val = (ssize_t)-EINVAL;

	if(fd && src) {
		ret_val = fd->ops->write ?
			fd->ops->write(fd, src, slen) : -EOPNOTSUPP;
	}

	return(ret_val);
}

int m10k_fd_accept(m10k_fd *src, m10k_fd **dst)
{
	int ret_val;
	m10k_fd *fd;

	ret_val = -EINVAL;
	fd = NULL;

	if(src && dst) {
		ret_val = src->ops->accept ?
			src->ops->accept(src, dst) : -EOPNOTSUPP;
	}

	return(ret_val);
}

int m10k_fd_set_callback(m10k_fd *fd, m10k_fd_event ev, m10k_fd_func *func, void *data)
{
	int ret_val;

	ret_val = -EINVAL;

	if(fd && ev >= 0 && ev < M10K_FD_EVENT_NUM) {
		_LOCK(fd);

		fd->events[ev].handler = func;
		fd->events[ev].arg = data;

		_UNLOCK(fd);

		ret_val = 0;
	}

	return(ret_val);
}

int m10k_fd_get_fd(m10k_fd *fd)
{
	int ret_val;

	ret_val = -EINVAL;

	if(fd) {
		_LOCK(fd);
		ret_val = fd->fd;
		_UNLOCK(fd);
	}

	return(ret_val);
}

int m10k_fd_notify(m10k_fd *fd, m10k_fd_event ev, void *arg)
{
	int ret_val;

	ret_val = -EINVAL;

	if(fd && ev >= 0 && ev < M10K_FD_EVENT_NUM) {
		struct _fd_event cb;

		ret_val = -ENOTSUP;

		_LOCK(fd);
	    cb = fd->events[ev];
		_UNLOCK(fd);

		/* call the handler outside of the lock */
		if(cb.handler) {
			cb.handler(fd, ev, cb.arg, arg);
		}

		ret_val = 0;
	}

	return(ret_val);
}
