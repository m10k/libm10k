/*
 * thread.c - This file is part of libm10k
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
#include <pthread.h>
#include <errno.h>
#include <pthread.h>
#include <assert.h>

struct _m10k_thread {
	m10k_mutex lock;
	m10k_thread_flags flags;
	pthread_t thread;

	void* (*func)(void*);
	void *arg;
	void *ret_val;
};

#define _LOCK(t)   m10k_mutex_lock(&((t)->lock))
#define _UNLOCK(t) m10k_mutex_unlock(&((t)->lock))

/* make use of error-checking mutexes if _GNU_SOURCE is defined */
#ifdef _GNU_SOURCE
int m10k_mutex_init(m10k_mutex *mtx)
{
	pthread_mutexattr_t attr;
	int ret_val;

	ret_val = -pthread_mutexattr_init(&attr);

	if(!ret_val) {
		ret_val = -pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK_NP);

		if(!ret_val) {
			ret_val = -pthread_mutex_init(mtx, &attr);
		}

		pthread_mutexattr_destroy(&attr);
	}

	return(ret_val);
}
#endif /* _GNU_SOURCE */

int m10k_thread_new(m10k_thread **dst)
{
	m10k_thread *t;
	int ret_val;

	ret_val = -EINVAL;

	if(dst) {
		ret_val = m10k_salloc(t);

		if(ret_val < 0) {
			ret_val = -ENOMEM;
		} else {
			assert(m10k_mutex_init(&(t->lock)) == 0);
			t->flags = M10K_THREAD_FLAG_INIT;
		}

		/* will be either NULL or the m10k_thread */
		*dst = t;
	}

	return(ret_val);
}

int m10k_thread_free(m10k_thread **t)
{
	int ret_val;

	ret_val = -EINVAL;

	if(t && *t) {
		m10k_thread_join(*t, NULL);
		assert(m10k_mutex_destroy(&((*t)->lock)) == 0);
		m10k_mem_unref((void**)t);

		ret_val = 0;
	}

	return(ret_val);
}

int m10k_thread_set_flags(m10k_thread *t, m10k_thread_flags mask, m10k_thread_flags flags)
{
	int ret_val;

	ret_val = -EINVAL;

	if(t && mask) {
		_LOCK(t);

		if(t->flags & M10K_THREAD_FLAG_RUNNING) {
			ret_val = -EINPROGRESS;
		} else {
			t->flags = (t->flags & ~mask) | (flags & mask);
			ret_val = 0;
		}

		_UNLOCK(t);
	}

	return(ret_val);
}

int m10k_thread_get_flags(m10k_thread *t, m10k_thread_flags *dst)
{
	int ret_val;

	ret_val = -EINVAL;

	if(t && dst) {
		_LOCK(t);
		*dst = t->flags;
		_UNLOCK(t);
	}

	return(ret_val);
}

static void *__m10k_thread_run(void *arg)
{
	m10k_thread *t;

	t = (m10k_thread*)arg;

	assert(t);
	assert(t->func);

	return(t->func(t->arg));
}

int m10k_thread_start(m10k_thread *t, void* (*func)(void*), void *arg)
{
	int ret_val;

	ret_val = -EINVAL;

	if(t) {
		_LOCK(t);

		if(t->flags & M10K_THREAD_FLAG_RUNNING) {
			ret_val = -EALREADY;
		} else {
			t->arg = arg;
			t->func = func;

			ret_val = -pthread_create(&(t->thread), NULL, __m10k_thread_run, t);

			if(!ret_val) {
				t->flags = M10K_THREAD_FLAG_RUNNING;
			}
		}

		_UNLOCK(t);
	}

	return(ret_val);
}

int m10k_thread_stop(m10k_thread *t)
{
	int ret_val;

	ret_val = -EINVAL;

	if(t) {
		ret_val = -EALREADY;

		_LOCK(t);

		if(t->flags & M10K_THREAD_FLAG_RUNNING) {
			t->flags |= M10K_THREAD_FLAG_STOP;
			ret_val = 0;
		}

		_UNLOCK(t);
	}

	return(ret_val);
}

int m10k_thread_cancel(m10k_thread *t, void **ret)
{
	int ret_val;

	ret_val = -EINVAL;

	if(t) {
		_LOCK(t);

		if(t->flags & M10K_THREAD_FLAG_RUNNING) {
			ret_val = -pthread_cancel(t->thread);
		} else {
			ret_val = -EALREADY;
		}

		_UNLOCK(t);

		if(ret_val >= 0) {
			ret_val = m10k_thread_join(t, ret);
		}
	}

	return(ret_val);
}

int m10k_thread_join(m10k_thread *t, void **ret)
{
	int ret_val;

	ret_val = -EINVAL;

	if(t) {
		_LOCK(t);

		ret_val = -pthread_join(t->thread, &(t->ret_val));

		if(!ret_val && ret) {
			*((size_t*)ret) = (size_t)t->ret_val;
		}

		_UNLOCK(t);
	}

	return(ret_val);
}
