#ifndef ROHC_LOG_H
#define ROHC_LOG_H

#ifdef __cplusplus
extern "C"
{
#endif

#if defined(ROHC_USE_EXTERNAL_ZLOG)

#include "zlog.h"

#define _LOG_INIT(config)         dzlog_init()
#define _LOG_DEINIT()             zlog_fini()

#define _LOG_TRACE(format, ...)   dzlog_debug(format, ...)
#define _LOG_DEBUG(format, ...)   dzlog_debug(format, ...)
#define _LOG_INFO(format, ...)    dzlog_info(format, ...)
#define _LOG_WARN(format, ...)    dzlog_warn(format, ...)
#define _LOG_ERROR(format, ...)   dzlog_error(format, ...)

#else
#include <stdio.h>
#define _LOG_INIT(config)
#define _LOG_DEINIT()

#define _LOG_TRACE(format, ...)  fprintf(stdout, format)
#define _LOG_DEBUG(format, ...)  fprintf(stdout, format)
#define _LOG_INFO(format, ...)   fprintf(stdout, format)
#define _LOG_WARN(format, ...)   fprintf(stderr, format)
#define _LOG_ERROR(format, ...)  fprintf(stderr, format)
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

#if defined(ENABLE_ROHC_DEBUG_LOG)
#define ROHC_LOG_TRACE(format, ...)  _LOG_TRACE(format)
#define ROHC_LOG_DEBUG(format, ...)  _LOG_DEBUG(format)
#define ROHC_LOG_INFO(format, ...)   _LOG_INFO(format)
#define ROHC_LOG_WARN(format, ...)   _LOG_WARN(format)
#define ROHC_LOG_ERROR(format, ...)  _LOG_ERROR(format)

#else /* ENABLE_ROHC_DEBUG_LOG*/

#define ROHC_LOG_TRACE(format, ...)
#define ROHC_LOG_DEBUG(format, ...)
#define ROHC_LOG_INFO(format, ...)
#define ROHC_LOG_WARN(format, ...)   _LOG_WARN(format)
#define ROHC_LOG_ERROR(format, ...)  _LOG_ERROR(format)

#endif /* ENABLE_ROHC_DEBUG_LOG */

#endif  /* DISABLE_ALL_ROHC_LOG */


#ifdef __cplusplus
}
#endif

#endif /* ROHC_LOG_H */

