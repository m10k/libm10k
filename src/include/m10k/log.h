/*
 * log.h - This file is part of libm10k
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

#ifndef _M10K_LOG_H
#define _M10K_LOG_H

#include <stdio.h>
#include <string.h>
#include <syslog.h>

#ifdef _LIBM10K_SOURCE
#define LOG_TAG "libm10k"
#endif /* _LIBM10K_SOURCE */

typedef enum {
	M10K_LOG_LEVEL_ERROR = 0,
	M10K_LOG_LEVEL_WARNING,
	M10K_LOG_LEVEL_NOTICE,
	M10K_LOG_LEVEL_INFO,
	M10K_LOG_LEVEL_DEBUG,
	M10K_LOG_LEVEL_NUM
} m10k_log_level;

typedef enum {
	M10K_LOG_TYPE_STDERR = 0,
	M10K_LOG_TYPE_SYSLOG,
	M10K_LOG_TYPE_FILE,
	M10K_LOG_TYPE_NUM
} m10k_log_type;

int m10k_log_open(const m10k_log_type, const char*);
int m10k_log_printf(const m10k_log_level, const char*, const char*, ...);
int m10k_log_close(void);
int m10k_log_set_verbosity(const m10k_log_level);

const char* m10k_log_level_name(const m10k_log_level);
const char* m10k_log_type_name(const m10k_log_type);

#define m10k_E(fmt,...) m10k_log_printf(M10K_LOG_LEVEL_ERROR, LOG_TAG, (fmt), ##__VA_ARGS__)
#define m10k_W(fmt,...) m10k_log_printf(M10K_LOG_LEVEL_ERROR, LOG_TAG, (fmt), ##__VA_ARGS__)
#define m10k_N(fmt,...) m10k_log_printf(M10K_LOG_LEVEL_NOTICE, LOG_TAG, (fmt), ##__VA_ARGS__)
#define m10k_I(fmt,...) m10k_log_printf(M10K_LOG_LEVEL_INFO, LOG_TAG, (fmt), ##__VA_ARGS__)
#define m10k_D(fmt,...) m10k_log_printf(M10K_LOG_LEVEL_DEBUG, LOG_TAG, (fmt), ##__VA_ARGS__)
#define m10k_P(str,err) m10k_log_printf(M10K_LOG_LEVEL_ERROR, LOG_TAG, "%s: %s", (str), \
										strerror(-(err)))

#endif /* _M10K_LOG_H */
