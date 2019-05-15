/*
 * log.c - This file is part of libm10k
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
#include <syslog.h>
#include <stdarg.h>
#include <errno.h>
#include <stdio.h>
#include <time.h>

static const int _syslog_level[] = {
	LOG_ERR,
	LOG_WARNING,
	LOG_NOTICE,
	LOG_INFO,
	LOG_DEBUG
};

static const char *_type_name[] = {
	"stderr",
	"syslog",
	"file"
};

static const char *_lvl_name[] = {
	"ERROR",
	"WARNING",
	"NOTICE",
	"INFO",
	"DEBUG"
};

static const char *_lvl_tag[] = {
	"ERR",
	"WRN",
	"NTC",
	"INF",
	"DBG"
};

static m10k_log_level _verbosity = M10K_LOG_LEVEL_ERROR;
static m10k_log_type  _type      = M10K_LOG_TYPE_STDERR;
static FILE           *_logfile  = NULL;

int m10k_log_open(const m10k_log_type type, const char *name)
{
	int ret_val;

	ret_val = -EINVAL;

	if(type > 0 && type < M10K_LOG_TYPE_NUM && name) {
		ret_val = -EALREADY;

		if(_type == M10K_LOG_TYPE_STDERR) {
			switch(type) {
			case M10K_LOG_TYPE_SYSLOG:
				openlog(name, LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL7);
				ret_val = 0;
				break;

			case M10K_LOG_TYPE_FILE:
				_logfile = fopen(name, "a+");

				if(_logfile) {
					ret_val = 0;
				} else {
					ret_val = -errno;
				}
				break;

			default:
				break;
			}

			if(!ret_val) {
				_type = type;
			}
		}
	}

	return(ret_val);
}

int m10k_log_printf(const m10k_log_level level, const char *tag, const char *fmt, ...)
{
	int ret_val;
	va_list args;

	ret_val = -ENOMEDIUM;

	if(_type >= 0 && _type < M10K_LOG_TYPE_NUM) {
		/* only log messages that don't exceed the verbosity level */
		if(level <= _verbosity) {
			va_start(args, fmt);

			if(_type == M10K_LOG_TYPE_SYSLOG) {
				char line[256];

#define VALID_LVL(l)     ((l) >= 0 && (l) < M10K_LOG_LEVEL_NUM)
#define LVL_TO_SYSLOG(l) (VALID_LVL(l) ? _syslog_level[l] : LOG_WARNING)

				/* prefix format string with log tag and level */
				snprintf(line, sizeof(line), "<%s> [%s] %s", _lvl_tag[level], tag, fmt);
				vsyslog(LVL_TO_SYSLOG(level), line, args);

#undef VALID_LVL
#undef LVL_TO_SYSLOG

			} else {
				FILE *out;
				char timestamp[24];
				time_t now;

				out = _logfile ? _logfile : stderr;
				now = time(NULL);

				strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));

				fprintf(out, "%s <%s> [%s] ", timestamp, _lvl_tag[level], tag);
				vfprintf(out, fmt, args);
				fprintf(out, "\n");
				fflush(out);
			}

			va_end(args);
		}

		ret_val = 0;
	}

	return(ret_val);
}

int m10k_log_close(void)
{
	int ret_val;

	ret_val = 0;

	switch(_type) {
	case M10K_LOG_TYPE_SYSLOG:
		closelog();
		break;

	case M10K_LOG_TYPE_FILE:
		if(_logfile) {
			fclose(_logfile);
			_logfile = NULL;
		} else {
			ret_val = -EBADF;
		}
		break;

	default:
		ret_val = -ENOMEDIUM;
		/* fall through */
	case M10K_LOG_TYPE_STDERR:
		/* nothing to do */
		break;
	}

	_type = M10K_LOG_TYPE_STDERR;

	return(ret_val);
}

int m10k_log_set_verbosity(const m10k_log_level verb)
{
	int ret_val;

	ret_val = -ERANGE;

	if(verb >= LOG_ERR && verb < M10K_LOG_LEVEL_NUM) {
		_verbosity = verb;
		ret_val = 0;
	}

	return(ret_val);
}

const char* m10k_log_level_name(const m10k_log_level lvl)
{
	if(lvl < 0 || lvl >= M10K_LOG_LEVEL_NUM) {
		return(NULL);
	}

	return(_lvl_name[lvl]);
}

const char* m10k_log_type_name(const m10k_log_type type)
{
	if(type < 0 || type >= M10K_LOG_TYPE_NUM) {
		return(NULL);
	}

	return(_type_name[type]);
}
