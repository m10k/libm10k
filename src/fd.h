#ifdef _LIBM10K_SOURCE

#ifndef _INTERNAL_FD_H
#define _INTERNAL_FD_H

#include <m10k/fd.h>
#include <stdlib.h>
#include <stdarg.h>

struct fd_ops {
	int     (*open)  (m10k_fd*, va_list);
	ssize_t (*read)  (m10k_fd*, void*, const size_t);
	ssize_t (*write) (m10k_fd*, const void*, const size_t);
	int     (*accept)(m10k_fd*, m10k_fd**);
	int     (*close) (m10k_fd*);
};

struct fd_dom {
	m10k_fd_type type;
	struct fd_ops *ops;
};

struct _fd_event {
	m10k_fd_func *handler;
	void *arg;
};

struct _m10k_fd {
	int fd;
	m10k_mutex lock;

	struct fd_ops *ops;
	struct sockaddr *addr;
	socklen_t addrlen;

	m10k_fd_dom dom;
	void *priv;

	struct _fd_event events[M10K_FD_EVENT_NUM];
};

#define FD_LOCK(f)   m10k_mutex_lock(&((f)->lock))
#define FD_UNLOCK(f) m10k_mutex_unlock(&((f)->lock))

int m10k_fd_get_fd(m10k_fd*);

#endif /* _INTERNAL_FD_H */

#endif /* _LIBM10K_SOURCE */
