#ifndef MUNINN_API_CONFIG_H
#define MUNINN_API_CONFIG_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <phnt_windows.h>
#include <phnt.h>

// Include SAL if available
#ifdef __has_include
#  if __has_include(<sal.h>)
#    include <sal.h>
#  endif
#endif

#ifdef __cplusplus
#define MUNINN_API extern "C"
#else
#define MUNINN_API
#endif

#ifdef _MSC_VER
#define MUNINN_CALL __fastcall
#else
#define MUNINN_CALL
#endif

// Fallback definitions if SAL macros are not already defined
#ifndef _In_
#define _In_
#endif

#ifndef _Out_
#define _Out_
#endif

#ifndef _Out_writes_
#define _Out_writes_(size)
#endif

#ifndef _Out_opt_
#define _Out_opt_
#endif

#endif // !MUNINN_API_CONFIG_H