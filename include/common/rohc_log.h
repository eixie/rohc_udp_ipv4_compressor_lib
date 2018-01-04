#ifndef ROHC_LOG_H
#define ROHC_LOG_H

#ifdef __cplusplus
extern "C"
{
#endif

//#define ROHC_USE_EXTERNAL_ZLOG

#if defined(ROHC_USE_EXTERNAL_ZLOG)

#include "zlog.h"

#define _LOG_INIT(config)         dzlog_init()
#define _LOG_DEINIT()             zlog_fini()

#define _LOG_TRACE(format, ...)   dzlog_debug(format, ##__VA_ARGS__)
#define _LOG_DEBUG(format, ...)   dzlog_debug(format, ##__VA_ARGS__)
#define _LOG_INFO(format, ...)    dzlog_info(format, ##__VA_ARGS__)
#define _LOG_WARN(format, ...)    dzlog_warn(format, ##__VA_ARGS__)
#define _LOG_ERROR(format, ...)   dzlog_error(format, ##__VA_ARGS__)

#else
#include <stdio.h>
#define _LOG_INIT(config)
#define _LOG_DEINIT()

#define _LOG_TRACE(format, ...)  fprintf(stdout, format, ##__VA_ARGS__)
#define _LOG_DEBUG(format, ...)  fprintf(stdout, format, ##__VA_ARGS__)
#define _LOG_INFO(format, ...)   fprintf(stdout, format, ##__VA_ARGS__)
#define _LOG_WARN(format, ...)   fprintf(stdout, format, ##__VA_ARGS__)
#define _LOG_ERROR(format, ...)  fprintf(stdout, format, ##__VA_ARGS__)
#endif /* ROHC_USE_EXTERNAL_ZLOG */


#if defined(DISABLE_ALL_ROHC_LOG)

#define ROHC_LOG_INIT(config)
#define ROHC_LOG_DEINIT()
#define ROHC_LOG_TRACE(format, ...)
#define ROHC_LOG_DEBUG(format, ...)
#define ROHC_LOG_INFO(format, ...)
#define ROHC_LOG_WARN(format, ...)
#define ROHC_LOG_ERROR(format, ...)

#else /* DISABLE_ALL_ROHC_LOG */

#define ROHC_LOG_INIT(config)        _LOG_INIT((config))
#define ROHC_LOG_DEINIT()            _LOG_DEINIT()


#if DEBUG

#define ROHC_LOG_TRACE(format, ...)  _LOG_TRACE(format, ##__VA_ARGS__)
#define ROHC_LOG_DEBUG(format, ...)  _LOG_DEBUG(format, ##__VA_ARGS__)
#define ROHC_LOG_INFO(format, ...)   _LOG_INFO(format, ##__VA_ARGS__)
#define ROHC_LOG_WARN(format, ...)   _LOG_WARN(format, ##__VA_ARGS__)
#define ROHC_LOG_ERROR(format, ...)  _LOG_ERROR(format, ##__VA_ARGS__)

#else /* DEBUG*/

#define ROHC_LOG_TRACE(format, ...)
#define ROHC_LOG_DEBUG(format, ...)
#define ROHC_LOG_INFO(format, ...)   _LOG_INFO(format, ##__VA_ARGS__)
#define ROHC_LOG_WARN(format, ...)   _LOG_WARN(format, ##__VA_ARGS__)
#define ROHC_LOG_ERROR(format, ...)  _LOG_ERROR(format, ##__VA_ARGS__)

#endif /* DEBUG */

#endif  /* DISABLE_ALL_ROHC_LOG */


#ifdef __cplusplus
}
#endif

#endif /* ROHC_LOG_H */
