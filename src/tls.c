/*
 * tls.c - This file is part of libm10k
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
#include <tls.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <net/if.h>
#include <netdb.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include "fd.h"

#define BACKLOG 8

static int     _tls_open (m10k_fd*, va_list);
static int     _tls_close(m10k_fd*);
static ssize_t _tls_read (m10k_fd*, void*, const size_t);
static ssize_t _tls_write(m10k_fd*, const void*, const size_t);

struct fd_ops _dom_tls = {
	.open  = _tls_open,
	.close = _tls_close,
	.read  = _tls_read,
	.write = _tls_write
};

struct tls_priv {
	struct tls *conn;
	struct tls_config *config;
	struct sockaddr_in6 addr;

	m10k_fd_type type;
	char *host;
	short port;
	char *cacert;
	char *cert;
	char *pkey;
};

static void _priv_free(struct tls_priv **priv)
{
	if(priv && *priv) {
		if((*priv)->config) {
			tls_config_free((*priv)->config);
		}

		m10k_mem_unref((void**)priv);
	}

	return;
}

static int _tls_prepare(struct tls_priv *priv)
{
	int ret_val;

	ret_val = 0;
	priv->config = tls_config_new();

	if(!priv->config) {
		ret_val = -ENOMEM;
		goto gtfo;
	}

	tls_init();

	ret_val = tls_config_set_ca_file(priv->config,
									 priv->cacert);

	if(ret_val < 0) {
		ret_val = -EKEYREJECTED;
		goto gtfo;
	}

	/* do not set the keypair if it has not been provided */
	if(priv->cert && priv->pkey) {
		ret_val = tls_config_set_keypair_file(priv->config,
											  priv->cert,
											  priv->pkey);

		if(ret_val < 0) {
			ret_val = -EKEYREJECTED;
			goto gtfo;
		}
	}

	switch(priv->type) {
	case M10K_FD_TYPE_SERVER:
		m10k_I("Server mode: Expecting client to present a valid certificate");

		tls_config_verify_client(priv->config);
		priv->conn = tls_server();
		break;

	case M10K_FD_TYPE_CLIENT:
		priv->conn = tls_client();
		break;

	default:
		priv->conn = NULL;
		ret_val = -EBADFD;
		break;
	}

	if(!priv->conn) {
		/* don't override ret_val if it's -EBADFD */
		if(!ret_val) {
			ret_val = -ENOMEM;
		}
		goto gtfo;
	}

	if(tls_configure(priv->conn, priv->config) < 0) {
		ret_val = -EINVAL;
		m10k_E("tls_configure: %s", tls_error(priv->conn));
		goto gtfo;
	}

gtfo:
	if(ret_val < 0) {
		if(priv->config) {
			tls_config_free(priv->config);
		}
	}

	return(ret_val);
}

static int _inet6_lookup(struct sockaddr_in6 *addr, const char *host, const short port)
{
	int ret_val;
	struct addrinfo hints;
	struct addrinfo *res;
	char portstr[6];

	snprintf(portstr, sizeof(portstr), "%hd", port);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_STREAM;

	/* we're not picky: we'll use the first result */

	ret_val = getaddrinfo(host, portstr, &hints, &res);

	if(ret_val) {
		/* non-zero means failure */
		m10k_E("getaddrinfo: %s", gai_strerror(ret_val));
		ret_val = -ENETUNREACH;
	} else if(res) {
		size_t len;

		/* make sure we don't copy more than the destination can hold */
		len = res->ai_addrlen < sizeof(*addr) ?
			res->ai_addrlen : sizeof(*addr);
		memcpy(addr, res->ai_addr, len);
		freeaddrinfo(res);
		ret_val = 0;
	} else {
		ret_val = -EHOSTUNREACH;
	}

	return(ret_val);
}

static int _socket_open(struct tls_priv *priv)
{
	int ret_val;
	int sock;

	sock = socket(PF_INET6, SOCK_STREAM, 0);

	if(sock < 0) {
		ret_val = -errno;
	} else {
		ret_val = _inet6_lookup(&(priv->addr), priv->host, priv->port);

		if(ret_val < 0) {
			m10k_P("_inet6_lookup", ret_val);
			goto gtfo;
		}

		ret_val = 1;

		/* attempt to reuse the address */
		if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
					  &ret_val, sizeof(ret_val)) < 0) {
			m10k_P("setsockopt", -errno);
		}

		ret_val = 0;

		switch(priv->type) {
		case M10K_FD_TYPE_SERVER:
			if(bind(sock, (struct sockaddr*)&(priv->addr),
					sizeof(priv->addr)) < 0) {
				ret_val = -errno;
				m10k_P("bind", ret_val);
				break;
			}

			if(listen(sock, BACKLOG) < 0) {
				ret_val = -errno;
				m10k_P("listen", ret_val);
			}

			break;

		case M10K_FD_TYPE_CLIENT:
			if(connect(sock, (struct sockaddr*)&(priv->addr),
					   sizeof(priv->addr)) < 0) {
				ret_val = -errno;
				m10k_P("connect", ret_val);
			}

			break;

		default:
			ret_val = -EBADFD;
			break;
		}
	}

gtfo:
	if(ret_val < 0) {
		if(sock >= 0) {
			close(sock);
		}
	} else {
		ret_val = sock;
	}

	return(ret_val);
}

static int _tls_open(m10k_fd *fd, va_list args)
{
	struct tls_priv *priv;
	int ret_val;
	int sock;

	ret_val = -EINVAL;

	if(!fd) {
		goto gtfo;
	}

	ret_val = m10k_salloc(priv);

	if(ret_val) {
		goto gtfo;
	}

	priv->type = (m10k_fd_type)va_arg(args, int);
	priv->host = va_arg(args, char*);
	priv->port = (short)va_arg(args, int);
	priv->cacert = va_arg(args, char*);
	priv->cert = va_arg(args, char*);
	priv->pkey = va_arg(args, char*);

	sock = _socket_open(priv);

	if(ret_val < 0) {
		m10k_P("_socket_open", ret_val);
		goto gtfo;
	}

	fd->fd = sock;

	ret_val = _tls_prepare(priv);

	if(ret_val < 0) {
		m10k_P("_tls_prepare", ret_val);
		goto gtfo;
	}

	if(priv->type == M10K_FD_TYPE_CLIENT) {
		char addr[INET6_ADDRSTRLEN];
		char *pc;

		/* remove the interface bit in case it is a link-local address like fe80::f00:1%eth0 */
		snprintf(addr, sizeof(addr), "%s", priv->host);

		if((pc = strchr(addr, '%'))) {
			*pc = 0;
		}

		ret_val = tls_connect_socket(priv->conn, fd->fd, addr);

		if(ret_val < 0) {
			m10k_E("tls_connect_socket: %s", tls_error(priv->conn));
			ret_val = -ECONNREFUSED;

			/* not necessary, but in case code is added in between */
			goto gtfo;
		}
	}

gtfo:
	if(ret_val) {
		/* there was an error */

		if(priv) {
			_priv_free(&priv);
		}
	} else {
		fd->priv = priv;
	}

	return(ret_val);
}

static int _tls_close(m10k_fd *fd)
{
	struct tls_priv *priv;
	int ret_val;

	ret_val = -EINVAL;

	if(fd) {
		ret_val = -EBADFD;
		priv = (struct tls_priv*)fd->priv;

		if(priv) {
			do {
				ret_val = tls_close(priv->conn);
			} while(ret_val == TLS_WANT_POLLIN ||
					ret_val == TLS_WANT_POLLOUT);

			/* pass the original pointer since it will be set to NULL */
			_priv_free((struct tls_priv**)&(fd->priv));
		}
	}

	return(ret_val);
}

static ssize_t _tls_read(m10k_fd *fd, void *dst, const size_t dsize)
{
	ssize_t ret_val;
	struct tls_priv *priv;

	ret_val = (ssize_t)-EINVAL;

	if(fd) {
		ret_val = (ssize_t)-EBADFD;
		priv = (struct tls_priv*)fd->priv;

		if(priv) {
			ret_val = (ssize_t)-EOPNOTSUPP;

			if(priv->type == M10K_FD_TYPE_CLIENT) {
				ret_val = tls_read(priv->conn, dst, dsize);

				if(ret_val < 0) {
					m10k_E("tls_read: %s", tls_error(priv->conn));
					ret_val = (ssize_t)-EIO;
				}
			}
		}
	}

	return(ret_val);
}

static ssize_t _tls_write(m10k_fd *fd, const void *src, const size_t slen)
{
	ssize_t ret_val;
	struct tls_priv *priv;

	ret_val = (ssize_t)-EINVAL;

	if(fd) {
		ret_val = (ssize_t)-EBADFD;
		priv = (struct tls_priv*)fd->priv;

		if(priv) {
			ret_val = (ssize_t)-EOPNOTSUPP;

			if(priv->type == M10K_FD_TYPE_CLIENT) {
				ret_val = tls_write(priv->conn, src, slen);

				if(ret_val < 0) {
					m10k_E("tls_write: %s", tls_error(priv->conn));
					ret_val = -EIO;
				}
			}
		}
	}

	return(ret_val);
}
