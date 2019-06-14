/*
 * unix.c - This file is part of libm10k
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
#include <m10k/types.h>
#include <m10k/mem.h>
#include <m10k/log.h>
#include <m10k/fd.h>
#include <m10k/thread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include "fd.h"

#define BACKLOG 8

static int     _unix_open  (m10k_fd*, va_list);
static ssize_t _unix_read  (m10k_fd*, void*, const size_t);
static ssize_t _unix_write (m10k_fd*, const void*, const size_t);
static int     _unix_accept(m10k_fd*, m10k_fd**);
static int     _unix_close (m10k_fd*);

struct fd_ops _unix_ops = {
	.open = _unix_open,
	.read = _unix_read,
	.write = _unix_write,
	.accept = _unix_accept,
	.close = _unix_close
};

struct fd_dom _dom_unix = {
	.type = M10K_FD_DOM_UNIX,
	.ops = &_unix_ops
};

struct unix_priv {
	struct sockaddr_un addr;
	m10k_fd_type type;
};

static int _unix_open_sock(struct unix_priv *priv)
{
	int ret_val;
	int sock;

	ret_val = -EINVAL;
	sock = -1;

	if(priv) {
		sock = socket(PF_UNIX, SOCK_SEQPACKET, 0);

		if(sock < 0) {
			ret_val = -errno;
			m10k_P("socket", ret_val);
			goto gtfo;
		}

		if(priv->type == M10K_FD_TYPE_SERVER) {
			ret_val = 1;

			/* attempt to reuse an existing socket */
			if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
						  &ret_val, sizeof(ret_val)) < 0) {
				m10k_P("setsockopt", -errno);
				/* not a critical error */
			}

			if(bind(sock, (struct sockaddr*)&(priv->addr),
					sizeof(priv->addr)) < 0) {
				ret_val = -errno;
				m10k_P("bind", ret_val);
				goto gtfo;
			}

			if(listen(sock, BACKLOG) < 0) {
				ret_val = -errno;
				m10k_P("listen", ret_val);
				goto gtfo;
			}
		} else {
			if(connect(sock, (struct sockaddr*)&(priv->addr),
					   sizeof(priv->addr)) < 0) {
				ret_val = -errno;
				m10k_P("connect", ret_val);
				goto gtfo;
			}
		}

		ret_val = sock;

	gtfo:
		if(ret_val < 0 && sock >= 0) {
			close(sock);
		}
	}

	return(ret_val);
}

static int _unix_open(m10k_fd *fd, va_list args)
{
	int ret_val;

	ret_val = -EINVAL;

	/*
	 * args shall contain these arguments:
	 *  m10k_fd_type type
	 *  const char*  path
	 */

	if(fd) {
		struct unix_priv *priv;
		m10k_fd_type type;
		const char *path;
		int sock;

		type = (m10k_fd_type)va_arg(args, int);
		path = (const char*)va_arg(args, char*);

		/* validate inputs */
		if(!m10k_fd_type_valid(type) || !path) {
			/* ret_val is still -EINVAL */
			goto gtfo;
		}

		ret_val = m10k_salloc(priv);

		if(ret_val < 0) {
			goto gtfo;
		}

		/* prepare the priv structure */
		priv->type = type;
		priv->addr.sun_family = AF_UNIX;
		snprintf(priv->addr.sun_path, sizeof(priv->addr.sun_path),
				 "%s", path);

		sock = _unix_open_sock(priv);

		/* if sock is negative, it's an error number */
		if(sock < 0) {
			ret_val = sock;
			goto gtfo;
		}

		/* finally, update the fd */
		FD_LOCK(fd);

		fd->fd = sock;
		fd->priv = priv;
		fd->addr = (struct sockaddr*)&(priv->addr);
		fd->addrlen = sizeof(priv->addr);

		FD_UNLOCK(fd);
	}

gtfo:
	return(ret_val);
}

static ssize_t _unix_read(m10k_fd *fd, void *dst, const size_t dsize)
{
	ssize_t ret_val;

	ret_val = (ssize_t)-EINVAL;

	if(fd && dst) {
		FD_LOCK(fd);
		ret_val = read(fd->fd, dst, dsize);
		FD_UNLOCK(fd);
	}

	return(ret_val);
}

static ssize_t _unix_write(m10k_fd *fd, const void *src, const size_t slen)
{
	ssize_t ret_val;

	ret_val = (ssize_t)-EINVAL;

	if(fd && src) {
		FD_LOCK(fd);
		ret_val = write(fd->fd, src, slen);
		FD_UNLOCK(fd);
	}

	return(ret_val);
}

static int _unix_accept(m10k_fd *fd, m10k_fd **client)
{
	int ret_val;

	ret_val = -EINVAL;

	if(fd && client) {
		m10k_fd *nfd;
		struct unix_priv *priv;

		nfd = NULL;
		priv = NULL;

		ret_val = m10k_salloc(nfd);

		if(ret_val < 0) {
			goto cleanup;
		}

		ret_val = m10k_salloc(priv);

		if(ret_val < 0) {
			goto cleanup;
		}

		assert(m10k_mutex_init(&(nfd->lock)) == 0);

		nfd->addr = (struct sockaddr*)&(priv->addr);
		nfd->addrlen = sizeof(priv->addr);
		nfd->priv = priv;

		/* perform operations that depend on fd */
		FD_LOCK(fd);

		nfd->dom = fd->dom;
		nfd->ops = fd->ops;
		memcpy(&(nfd->events), &(fd->events), sizeof(nfd->events));

		nfd->fd = accept(fd->fd, nfd->addr, &nfd->addrlen);

		/* pthread_mutex_unlock() may modify errno */
		if(nfd->fd < 0) {
			ret_val = -errno;
		}

		FD_UNLOCK(fd);

	cleanup:
		if(ret_val < 0) {
			/* accept failed - clean up */
			if(priv) {
				m10k_unref(priv);
			}

			if(nfd) {
				m10k_mutex_destroy(&(nfd->lock));
				m10k_unref(nfd);
			}
		}

		/* the new m10k_fd or NULL */
		*client = nfd;
	}

	return(ret_val);
}

static int _unix_close(m10k_fd *fd)
{
	/* nothing to do - close() will be called at the m10k_fd layer */
	return(0);
}
