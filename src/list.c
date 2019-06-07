/*
 * list.c - This file is part of libm10k
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
#include <m10k/thread.h>
#include <m10k/list.h>
#include <assert.h>
#include <errno.h>

struct _item {
	struct _item *next;
	m10k_mutex lock;
	void *data;
};

struct _m10k_list {
	m10k_mutex lock;

	struct _item *head;
	struct _item *tail;
	size_t nitems;
};

#define _LOCK(l)   m10k_mutex_lock(&((l)->lock))
#define _UNLOCK(l) m10k_mutex_unlock(&((l)->lock))

int m10k_list_new(m10k_list **list)
{
	int ret_val;

	ret_val = -EINVAL;

	if(list) {
		ret_val = m10k_mem_alloc((void**)list, sizeof(**list));
	}

	return(ret_val);
}

int m10k_list_free(m10k_list **list)
{
	int ret_val;

	ret_val = -EINVAL;

	if(list && *list) {
		_LOCK(*list);

		for(ret_val = 0; (*list)->head; ret_val++) {
			struct _item *next;

			/* make sure the item is not in use */
			_LOCK((*list)->head);
			next = (*list)->head->next;
			_UNLOCK((*list)->head);

			m10k_mutex_destroy(&((*list)->head->lock));
			m10k_mem_unref((void**)&((*list)->head));
			(*list)->head = next;
		}

		_UNLOCK(*list);

		m10k_mutex_destroy(&((*list)->lock));
		m10k_mem_unref((void**)list);
	}

	return(ret_val);
}

int m10k_list_prepend(m10k_list *list, void *data)
{
	int ret_val;

	ret_val = -EINVAL;

	if(list && data) {
		struct _item *item;

		ret_val = m10k_salloc(item);

		if(!ret_val) {
			m10k_mutex_init(&(item->lock));
			item->data = data;

			_LOCK(list);

			item->next = list->head;
			list->head = item;
			if(!list->tail) {
				list->tail = item;
			}
			list->nitems++;

			_UNLOCK(list);
		}
	}

	return(ret_val);
}

int m10k_list_append(m10k_list *list, void *data)
{
	int ret_val;

	ret_val = -EINVAL;

	if(list && data) {
		struct _item *item;

		ret_val = m10k_salloc(item);

		if(!ret_val) {
			m10k_mutex_init(&(item->lock));
			item->data = data;

			_LOCK(list);

			if(list->tail) {
				_LOCK(list->tail);
				list->tail->next = item;
				_UNLOCK(list->tail);
			} else {
				list->head = item;
			}

			list->tail = item;
			list->nitems++;

			_UNLOCK(list);
		}
	}

	return(ret_val);
}

int m10k_list_remove(m10k_list *list, void *data)
{
	int ret_val;

	ret_val = -EINVAL;

	if(list && data) {
		struct _item **ptr;
		m10k_mutex *locked;

		ret_val = -ENOENT;
		locked = NULL;

		_LOCK(list);

		for(ptr = &(list->head); *ptr; ptr = &((*ptr)->next)) {
			_LOCK(*ptr);
			if(locked) {
				m10k_mutex_unlock(locked);
			}
			locked = &((*ptr)->lock);

			if((*ptr)->data == data) {
				struct _item *free_me;

				free_me = *ptr;
				*ptr = (*ptr)->next;

				_UNLOCK(free_me);
				locked = NULL;
				m10k_mutex_destroy(&(free_me->lock));
				m10k_unref(free_me);

				if(!*ptr) {
					if(ptr == &(list->head)) {
						list->head = NULL;
						list->tail = NULL;
					} else {
						list->tail = (struct _item*)ptr;
					}
				}

				list->nitems--;
				ret_val = 0;
				break;
			}
		}

		if(locked) {
			m10k_mutex_unlock(locked);
		}

		_UNLOCK(list);
	}

	return(ret_val);
}

void* m10k_list_find(m10k_list *list, int(*cmp)(void*, void*), void *arg)
{
	void *ret_val;

	ret_val = NULL;

	if(list && cmp) {
		struct _item *item;
		m10k_mutex *locked;

		_LOCK(list);
		locked = &(list->lock);

		for(item = list->head; item; item = item->next) {
			_LOCK(item);
			m10k_mutex_unlock(locked);
			locked = &(item->lock);

			if(!cmp(item->data, arg)) {
				ret_val = item->data;
				break;
			}
		}

		m10k_mutex_unlock(locked);
	}

	return(ret_val);
}

int m10k_list_foreach(m10k_list *list, int (*func)(void*, void*), void *arg)
{
	int ret_val;

	ret_val = -EINVAL;

	if(list && func) {
		struct _item *cur;
		m10k_mutex *locked;
		void **items;
		size_t nitems;
		size_t idx;

		idx = 0;

		_LOCK(list);
		locked = &(list->lock);

		nitems = list->nitems;
		ret_val = m10k_mem_alloc((void**)&items, sizeof(items) * nitems);

		if(!ret_val) {
			for(cur = list->head; cur; cur = cur->next) {
				_LOCK(cur);
				m10k_mutex_unlock(locked);
				locked = &(cur->lock);
				items[idx++] = cur->data;
			}
		}

		m10k_mutex_unlock(locked);

		if(!ret_val) {
			for(idx = 0; idx < nitems; idx++) {
				if(func(items[idx], arg) < 0) {
					break;
				}
			}

			m10k_unref(items);
			ret_val = (int)idx;
		}
	}

	return(ret_val);
}

int m10k_list_flush(m10k_list *list)
{
	int ret_val;

	ret_val = -EINVAL;

	if(list) {
		_LOCK(list);

		for(ret_val = 0; list->head; ret_val++) {
			struct _item *next;

			/* make sure the item is not in use */
			_LOCK(list->head);
			next = list->head->next;
			_UNLOCK(list->head);

			/*
			 * We can be sure the head won't be locked by someone else
			 * since we still hold a lock on the list, and these functions
			 * never iterate over the list backwards
			 */
			m10k_mutex_destroy(&(list->head->lock));
			m10k_mem_unref((void**)&(list->head));
			list->head = next;
		}

		_UNLOCK(list);
	}

	return(ret_val);
}
