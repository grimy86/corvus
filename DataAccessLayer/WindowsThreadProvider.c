#include "WindowsThreadProvider.h"
#include "WindowsUtilityProvider.h"

#ifndef SUSPEND_THREAD_ERROR
#define SUSPEND_THREAD_ERROR -1
#endif // !SUSPEND_THREAD_ERROR

#ifndef RESUME_THREAD_ERROR
#define RESUME_THREAD_ERROR -1
#endif // !RESUME_THREAD_ERROR

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_SetThreadPriority(_In_ const DWORD priorityClass)
{
	return SetPriorityClass(
		GetCurrentProcess(),
		priorityClass) ?
		STATUS_SUCCESS :
		STATUS_UNSUCCESSFUL;
}

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_SetThreadSuspended(_In_ const DWORD threadId)
{
	HANDLE threadHandle = OpenThread(
		THREAD_SUSPEND_RESUME,
		FALSE,
		threadId);

	if (!DAL_IsValidHandle(threadHandle))
		return STATUS_INVALID_HANDLE;

	DWORD suspendCount =
		SuspendThread(threadHandle);

	if (suspendCount == SUSPEND_THREAD_ERROR)
		return STATUS_UNSUCCESSFUL;

	DAL_CloseHandle32(threadHandle);
	return STATUS_SUCCESS;
}

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_SetThreadResumed(_In_ const DWORD threadId)
{
	HANDLE threadHandle = OpenThread(
		THREAD_SUSPEND_RESUME,
		FALSE,
		threadId);

	if (!DAL_IsValidHandle(threadHandle))
		return STATUS_INVALID_HANDLE;

	DWORD suspendCount =
		ResumeThread(threadHandle);

	if (suspendCount == RESUME_THREAD_ERROR)
		return STATUS_UNSUCCESSFUL;

	DAL_CloseHandle32(threadHandle);
	return STATUS_SUCCESS;
}

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_GetThreadPriority(
	_In_ const HANDLE threadHandle,
	_Out_ INT* const pThreadPriority)
{
	if (!DAL_IsValidHandle(threadHandle))
		return STATUS_INVALID_PARAMETER_1;
	if (pThreadPriority == NULL)
		return STATUS_INVALID_PARAMETER_2;

	SetLastError(ERROR_SUCCESS);
	*pThreadPriority
		= GetThreadPriority(threadHandle);

	if (*pThreadPriority == THREAD_PRIORITY_ERROR_RETURN &&
		GetLastError() != ERROR_SUCCESS)
		return STATUS_UNSUCCESSFUL;

	return STATUS_SUCCESS;
}