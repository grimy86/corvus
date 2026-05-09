#ifndef WINDOWS_THREAD_PROVIDER_H
#define WINDOWS_THREAD_PROVIDER_H

#include "MuninnConfig.h"

#ifndef NTSTATUS
#define NTSTATUS LONG
#endif // !NTSTATUS

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_SetThreadPriority(_In_ const DWORD priorityClass);

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_SetThreadSuspended(_In_ const DWORD threadId);

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_SetThreadResumed(_In_ const DWORD threadId);

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_GetThreadPriority(
	_In_ const HANDLE threadHandle,
	_Out_ INT* const pThreadPriority);

#endif // !WINDOWS_THREAD_PROVIDER_H