/*
 * thread.h - This file is part of libm10k
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

#ifndef _M10K_THREAD_H
#define _M10K_THREAD_H

#include <pthread.h>
#include <semaphore.h>
#include <assert.h>

typedef pthread_mutex_t     m10k_mutex;
typedef sem_t               m10k_sem;
typedef struct _m10k_thread m10k_thread;

typedef enum {
	M10K_THREAD_FLAG_INIT = 0,
	M10K_THREAD_FLAG_RUNNING = (1 << 8),
	M10K_THREAD_FLAG_STOP = (1 << 9)
} m10k_thread_flags;

#ifdef _GNU_SOURCE
int m10k_mutex_init(m10k_mutex*);
#else /* !_GNU_SOURCE */
#define m10k_mutex_init(m)    (-pthread_mutex_init((m), NULL))
#endif /* !_GNU_SOURCE */
#define m10k_mutex_destroy(m) (-pthread_mutex_destroy((m)))

#define m10k_mutex_lock(m)    assert(pthread_mutex_lock((m)) == 0)
#define m10k_mutex_unlock(m)  assert(pthread_mutex_unlock((m)) == 0)

#define m10k_sem_init(s,v)    assert(sem_init((s), 0, (v)) == 0)
#define m10k_sem_destroy(s)   assert(sem_destroy((s)) == 0)
#define m10k_sem_wait(s)      assert(sem_wait((s)) == 0)
#define m10k_sem_post(s)      assert(sem_post((s)) == 0)

int m10k_thread_new(m10k_thread**);
int m10k_thread_free(m10k_thread**);

int m10k_thread_set_flags(m10k_thread*, m10k_thread_flags, m10k_thread_flags);
int m10k_thread_get_flags(m10k_thread*, m10k_thread_flags*);

int m10k_thread_start(m10k_thread*, void*(*)(void*), void*);
int m10k_thread_stop(m10k_thread*);
int m10k_thread_cancel(m10k_thread*, void**);
int m10k_thread_join(m10k_thread*, void**);

#endif /* _M10K_THREAD_H */
