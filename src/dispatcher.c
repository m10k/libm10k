/*
 * dispatcher.c - This file is part of libm10k
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
#include <m10k/fd.h>
#include <m10k/mem.h>
#include <m10k/log.h>
#include <m10k/dispatcher.h>
#include <m10k/thread.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <errno.h>
#include "fd.h"

#define _EVENT_MAX 16

struct _m10k_dispatcher {
	m10k_mutex lock;
	m10k_sem sem;
	m10k_thread *thread;
	m10k_dispatcher_flags flags;
	int epfd;
	int ret_val;
	int nfds;
};

#define _LOCK(d)   m10k_mutex_lock(&((d)->lock))
#define _UNLOCK(d) m10k_mutex_unlock(&((d)->lock))
#define _POST(d)   m10k_sem_post(&((d)->sem))
#define _WAIT(d)   m10k_sem_wait(&((d)->sem))

int m10k_dispatcher_new(m10k_dispatcher **dst)
{
	m10k_dispatcher *dp;
	int ret_val;

	ret_val = -EINVAL;

	if(dst) {
		ret_val = m10k_salloc(dp);

		if(!ret_val) {
			assert(m10k_mutex_init(&(dp->lock)) == 0);
			m10k_sem_init(&(dp->sem), 0);

			ret_val = m10k_thread_new(&(dp->thread));

			if(!ret_val) {
				dp->epfd = epoll_create1(EPOLL_CLOEXEC);

				if(dp->epfd < 0) {
					ret_val = -errno;
					m10k_P("epoll_create1", ret_val);
				}
			}
		}

		if(ret_val < 0) {
			if(dp) {
				m10k_dispatcher_free(&dp);
			}
		}

		*dst = dp;
	}

	return(ret_val);
}

int m10k_dispatcher_free(m10k_dispatcher **dp)
{
	int ret_val;

	ret_val = -EINVAL;

	if(dp && *dp) {
		ret_val = 0;

		_LOCK(*dp);

		m10k_sem_destroy(&((*dp)->sem));

		if((*dp)->epfd >= 0) {
			close((*dp)->epfd);
			(*dp)->epfd = -1;
		}

		if((*dp)->thread) {
			ret_val = m10k_thread_cancel((*dp)->thread, NULL);

			if(!ret_val) {
				m10k_thread_free(&((*dp)->thread));
			} else {
				m10k_P("m10k_thread_cancel", ret_val);
			}
		}

		_UNLOCK(*dp);

		m10k_mutex_destroy(&((*dp)->lock));
		m10k_unref(dp);
	}

	return(ret_val);
}

int m10k_dispatcher_add_fd(m10k_dispatcher *dp, m10k_fd *fd)
{
	struct epoll_event ev;
	int ret_val;

	ret_val = -EINVAL;

	if(dp && fd) {
		ev.events = EPOLLIN;
		ev.data.ptr = fd;

		ret_val = m10k_fd_get_fd(fd);

		if(ret_val < 0) {
			m10k_P("m10k_fd_get_fd", ret_val);
		} else {
			_LOCK(dp);

			if(epoll_ctl(dp->epfd, EPOLL_CTL_ADD, ret_val, &ev) < 0) {
				ret_val = -errno;
			} else {
				ret_val = 0;
			}

			dp->nfds++;
			_UNLOCK(dp);
			_POST(dp);
		}
	}

	return(ret_val);
}

int m10k_dispatcher_drop_fd(m10k_dispatcher *dp, m10k_fd *fd)
{
	int ret_val;

	ret_val = -EINVAL;

	if(dp && fd) {
		ret_val = m10k_fd_get_fd(fd);

		if(ret_val < 0) {
			m10k_P("m10k_fd_get_fd", ret_val);
		} else {
			_LOCK(dp);

			if(epoll_ctl(dp->epfd, EPOLL_CTL_DEL, ret_val, NULL) < 0) {
				ret_val = -errno;
			} else {
				ret_val = 0;
			}

			assert(dp->nfds > 0);
			dp->nfds--;

			_UNLOCK(dp);
		}
	}

	return(ret_val);
}

int m10k_dispatcher_set_flags(m10k_dispatcher *dp,
							  m10k_dispatcher_flags mask,
							  m10k_dispatcher_flags flags)
{
	int ret_val;

	ret_val = -EINVAL;

	if(dp) {
		_LOCK(dp);
		dp->flags = (dp->flags & ~mask) | (mask & flags);
		_UNLOCK(dp);
		ret_val = 0;
	}

	return(ret_val);
}

int m10k_dispatcher_get_flags(m10k_dispatcher *dp,
							  m10k_dispatcher_flags *dst)
{
	int ret_val;

	ret_val = -EINVAL;

	if(dp && dst) {
		_LOCK(dp);
		*dst = dp->flags;
		_UNLOCK(dp);
		ret_val = 0;
	}

	return(ret_val);
}

static void* __dispatcher_run(void *data)
{
	m10k_dispatcher *dp;
	m10k_dispatcher_flags flags;
	void *ret_val;
	int epfd;

	ret_val = NULL;
	dp = (m10k_dispatcher*)data;

	assert(dp);

	_LOCK(dp);
	epfd = dp->epfd;
	flags = dp->flags | M10K_DISPATCHER_FLAG_RUNNING;
	dp->flags = flags;
	_UNLOCK(dp);

	while(!(flags & M10K_DISPATCHER_FLAG_STOP)) {
		struct epoll_event ev[_EVENT_MAX];
		int n;

		/* make sure we don't end up in a tight loop if the dispatcher is empty */
		_LOCK(dp);
		n = dp->nfds;
		_UNLOCK(dp);

		if(n <= 0) {
			_WAIT(dp);
		}

		n = epoll_wait(epfd, ev, sizeof(ev) / sizeof(ev[0]), -1);

		if(n < 0) {
			if(errno != EINTR) {
				flags |= M10K_DISPATCHER_FLAG_STOP;
				m10k_P("epoll_wait", -errno);
			}
		} else {
			while(--n >= 0) {
				m10k_fd *fd;

				fd = (m10k_fd*)ev[n].data.ptr;

				if(ev[n].events & EPOLLIN) {
					m10k_fd_notify(fd, M10K_FD_EVENT_IN, dp);
				}

				if(ev[n].events & EPOLLOUT) {
					m10k_fd_notify(fd, M10K_FD_EVENT_OUT, dp);
				}

				if(ev[n].events & EPOLLERR) {
					m10k_fd_notify(fd, M10K_FD_EVENT_ERR, dp);
				}

				if(ev[n].events & EPOLLHUP) {
					m10k_fd_notify(fd, M10K_FD_EVENT_HUP, dp);
				}
			}
		}
	}

	return(ret_val);
}

int m10k_dispatcher_run(m10k_dispatcher *dp)
{
	m10k_dispatcher_flags flags;
	int ret_val;

	ret_val = -EINVAL;

	if(dp) {
		_LOCK(dp);
		flags = dp->flags;

		if(flags & M10K_DISPATCHER_FLAG_RUNNING) {
			ret_val = -EALREADY;
		} else if(flags & M10K_DISPATCHER_FLAG_THREADED) {
			ret_val = m10k_thread_start(dp->thread, __dispatcher_run, dp);

			if(!ret_val) {
				flags |= M10K_DISPATCHER_FLAG_RUNNING;
			}
		} else {
			ret_val = -EFAULT;
		}

		_UNLOCK(dp);

		/* start the dispatcher in this thread if it's not threaded */
		if(!(flags & (M10K_DISPATCHER_FLAG_THREADED | M10K_DISPATCHER_FLAG_RUNNING))) {
			__dispatcher_run(dp);
			ret_val = 0;
		}
	}

	return(ret_val);
}
