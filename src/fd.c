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

struct _callback {
	m10k_fd_func *handler;
	void *arg;
};

struct _m10k_fd {
	int fd;
	void *priv;
	m10k_mutex lock;

	struct _callback events[M10K_FD_EVENT_NUM];
};

#define _LOCK(f)   m10k_mutex_lock(&((f)->lock))
#define _UNLOCK(f) m10k_mutex_unlock(&((f)->lock))

int m10k_fd_new(m10k_fd **dst)
{
	int ret_val;
	m10k_fd *fd;

	ret_val = -EINVAL;

	if(dst) {
		ret_val = m10k_salloc(fd);

		if(!ret_val) {
			assert(m10k_mutex_init(&(fd->lock)) == 0);
			fd->fd = -1;
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
		m10k_fd_close(*fd);
		m10k_mem_unref((void**)fd);

		ret_val = 0;
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
			errno = 0;
			close(fd->fd);
			fd->fd = -1;
			ret_val = -errno;
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
		_LOCK(fd);

		if(fd->fd < 0) {
			ret_val = (ssize_t)-EBADF;
		} else {
			ret_val = read(fd->fd, dst, dsize);

			if(ret_val < 0) {
				ret_val = (ssize_t)-errno;
				m10k_P("read", ret_val);
			}
		}

		_UNLOCK(fd);
	}

	return(ret_val);
}

ssize_t m10k_fd_write(m10k_fd *fd, const void *src, const size_t slen)
{
	ssize_t ret_val;

	ret_val = (ssize_t)-EINVAL;

	if(fd && src) {
		_LOCK(fd);

		if(fd->fd < 0) {
			ret_val = (ssize_t)-EBADF;
		} else {
			ret_val = write(fd->fd, src, slen);

			if(ret_val < 0) {
				ret_val = (ssize_t)-errno;
				m10k_P("write", ret_val);
			}
		}

		_UNLOCK(fd);
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

int m10k_fd_set_priv(m10k_fd *fd, void *priv)
{
	int ret_val;

	ret_val = -EINVAL;

	if(fd) {
		_LOCK(fd);
		fd->priv = priv;
		_UNLOCK(fd);

		ret_val = 0;
	}

	return(ret_val);
}

int m10k_fd_get_priv(m10k_fd *fd, void **dst)
{
	int ret_val;

	ret_val = -EINVAL;

	if(fd && dst) {
		_LOCK(fd);
		*dst = fd->priv;
		_UNLOCK(fd);

		ret_val = 0;
	}

	return(ret_val);
}

int m10k_fd_set_fd(m10k_fd *fd, int llfd)
{
	int ret_val;

	ret_val = -EINVAL;

	if(fd) {
		_LOCK(fd);
		fd->fd = llfd;
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
		struct _callback cb;

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
