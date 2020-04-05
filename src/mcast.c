/*
 * mcast.c - This file is part of libm10k
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

#include <m10k/log.h>
#include <m10k/fd.h>
#include <m10k/mem.h>
#include <m10k/thread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include "fd.h"

struct mcast_priv {
	struct sockaddr_in6 addr;
};

static int     _mcast_open (m10k_fd*, va_list);
static int     _mcast_close(m10k_fd*);
static ssize_t _mcast_read (m10k_fd*, void*, const size_t);
static ssize_t _mcast_write(m10k_fd*, const void*, const size_t);

struct fd_ops _dom_mcast = {
	.open  = _mcast_open,
	.close = _mcast_close,
	.read  = _mcast_read,
	.write = _mcast_write
};

static int _mcast_open(m10k_fd *fd, va_list args)
{
	const char *iface;
	const char *addr;
    m10k_u16 port;
	int ret_val;

	/*
	 * _mcast_open() expects the following arguments in args:
	 *  1. the interface name [const char*]
	 *  2. the multicast address [const char*]
	 *  3. the port number [int]
	 */

	ret_val = -EINVAL;

	if(fd) {
		struct mcast_priv *priv;
		struct ipv6_mreq req;
		unsigned int ifidx;
		int sock;

		sock = -1;
		priv = NULL;

		iface = va_arg(args, char*);
		addr = va_arg(args, char*);
		port = (m10k_u16)va_arg(args, int);

		ifidx = if_nametoindex(iface);

		if(!ifidx) {
			m10k_P("if_nametoindex", -errno);
			ret_val = -ENODEV;
			goto cleanup;
		}

		ret_val = m10k_salloc(priv);

		if(ret_val < 0) {
			goto cleanup;
		}

		priv->addr.sin6_family = AF_INET6;
		priv->addr.sin6_port = htons(port);
		priv->addr.sin6_addr = in6addr_any;
		memset(&req, 0, sizeof(req));

		inet_pton(AF_INET6, addr, &(req.ipv6mr_multiaddr.s6_addr));
		req.ipv6mr_interface = ifidx;

		sock = socket(PF_INET6, SOCK_DGRAM, 0);

		if(sock < 0) {
			ret_val = -errno;
			m10k_P("socket", ret_val);
			goto cleanup;
		}

		ret_val = 1;

		if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &ret_val, sizeof(ret_val)) < 0) {
			m10k_P("setsockopt", -errno);
		}

		if(setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_IF, &ifidx, sizeof(ifidx)) < 0) {
			ret_val = -errno;
			m10k_P("setsockopt", ret_val);
			goto cleanup;
		}

		if(bind(sock, (struct sockaddr*)&(priv->addr), sizeof(priv->addr)) < 0) {
			ret_val = -errno;
			m10k_P("bind", ret_val);
			goto cleanup;
		}

		inet_pton(AF_INET6, addr, &(priv->addr.sin6_addr));

		if(setsockopt(sock, IPPROTO_IPV6, IPV6_JOIN_GROUP, &req, sizeof(req)) < 0) {
			ret_val = -errno;
			m10k_P("setsockopt", ret_val);
			goto cleanup;
		}

		ret_val = 0;

	cleanup:
		if(ret_val < 0) {
			if(sock >= 0) {
				close(sock);
			}

			if(priv) {
				m10k_unref(priv);
				fd->priv = NULL;
			}
		} else {
			/* store changes in the fd structure */
			FD_LOCK(fd);

			fd->priv = priv;
			fd->fd = sock;

			FD_UNLOCK(fd);
		}
	}

	return(ret_val);
}

static int _mcast_close(m10k_fd *fd)
{
	/* all we have to do is free the mcast_priv structure */
	if(fd->priv) {
		m10k_unref(fd->priv);
	}

	return(0);
}

static ssize_t _mcast_read(m10k_fd *fd, void *dst, const size_t dsize)
{
	ssize_t ret_val;

	ret_val = (ssize_t)-EINVAL;

	if(fd) {
		ret_val = read(fd->fd, dst, dsize);

		if(ret_val < 0) {
			ret_val = -errno;
			m10k_P("read", (int)ret_val);
		}
	}

	return(ret_val);
}

static ssize_t _mcast_write(m10k_fd *fd, const void *src, const size_t slen)
{
	ssize_t ret_val;

	ret_val = (ssize_t)-EINVAL;

	if(fd) {
		struct mcast_priv *priv;

		priv = (struct mcast_priv*)fd->priv;

		if(!priv) {
			/* file descriptor in bad state */
			ret_val = (ssize_t)-EBADFD;
		} else {
			ret_val = sendto(fd->fd, src, slen, 0, (struct sockaddr*)&(priv->addr), sizeof(priv->addr));

			if(ret_val < 0) {
				ret_val = -errno;
				m10k_P("sendto", (int)ret_val);
			}
		}
	}

	return(ret_val);
}
