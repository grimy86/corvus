#include "WindowsProvider32.h"
#include "DataUtilities.h"

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef SE_DEBUG_NAME_W
#define SE_DEBUG_NAME_W L"SeDebugPrivilege"
#endif // !SE_DEBUG_NAME_W

#ifndef SUSPEND_THREAD_ERROR
#define SUSPEND_THREAD_ERROR -1
#endif // !SUSPEND_THREAD_ERROR

#ifndef RESUME_THREAD_ERROR
#define RESUME_THREAD_ERROR -1
#endif // !RESUME_THREAD_ERROR

#ifndef PREALLOC_HANDLES
#define PREALLOC_HANDLES 1000
#endif // !PREALLOC_HANDLES

#ifndef MAX_PATH_LONG
#define MAX_PATH_LONG 32768
#endif // !MAX_PATH_LONG

MUNINN_API NTSTATUS MUNINN_CALL
MDAL_OpenProcessHandle32(
	_In_ const DWORD processId,
	_In_ const ACCESS_MASK accessMask,
	_Out_ HANDLE* const pHandle)
{
	if (!MDAL_IsValidProcessId(processId))
		return STATUS_INVALID_PARAMETER_1;
	if (pHandle == NULL)
		return STATUS_INVALID_PARAMETER_3;

	*pHandle = OpenProcess(
		accessMask,
		FALSE,
		processId);

	if (!MDAL_IsValidHandle(*pHandle))
		return STATUS_INVALID_HANDLE;

	return STATUS_SUCCESS;
}

MUNINN_API NTSTATUS MUNINN_CALL
MDAL_CloseHandle32(_In_ const HANDLE handle)
{
	if (!MDAL_IsValidHandle(handle))
		return STATUS_INVALID_PARAMETER_1;

	return CloseHandle(handle) ?
		STATUS_SUCCESS :
		STATUS_UNSUCCESSFUL;
}

MUNINN_API NTSTATUS MUNINN_CALL
MDAL_OpenTokenHandle32(
	_In_ const HANDLE processHandle,
	_In_ const ACCESS_MASK accessMask,
	_Out_ HANDLE* const pTokenHandle)
{
	if (!MDAL_IsValidHandle(processHandle))
		return STATUS_INVALID_PARAMETER_1;
	if (pTokenHandle == NULL)
		return STATUS_INVALID_PARAMETER_3;

	NTSTATUS status = OpenProcessToken(
		processHandle,
		accessMask,
		pTokenHandle) ?
		STATUS_SUCCESS :
		STATUS_UNSUCCESSFUL;

	if (!NT_SUCCESS(status))
		*pTokenHandle = NULL;

	return status;
}

MUNINN_API NTSTATUS MUNINN_CALL
MDAL_SetSeDebugPrivilege32()
{
	HANDLE tokenHandle = NULL;
	NTSTATUS status = MDAL_OpenTokenHandle32(
		GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
		&tokenHandle);

	if (!NT_SUCCESS(status))
		return status;

	if (!MDAL_IsValidHandle(tokenHandle))
		return STATUS_INVALID_HANDLE;

	LUID luid = { 0ul, 0l };
	status = LookupPrivilegeValueW(
		NULL,
		SE_DEBUG_NAME_W,
		&luid) ?
		STATUS_SUCCESS :
		STATUS_UNSUCCESSFUL;

	if (!NT_SUCCESS(status))
	{
		MDAL_CloseHandle32(tokenHandle);
		return status;
	}

	if (!MDAL_IsValidLuid(luid))
	{
		MDAL_CloseHandle32(tokenHandle);
		return STATUS_UNSUCCESSFUL;
	}

	TOKEN_PRIVILEGES privileges{};
	privileges.PrivilegeCount = 1;
	privileges.Privileges[0].Luid = luid;
	privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	status = AdjustTokenPrivileges(
		tokenHandle,
		FALSE,
		&privileges,
		sizeof(TOKEN_PRIVILEGES),
		nullptr,
		nullptr) ?
		STATUS_SUCCESS :
		STATUS_UNSUCCESSFUL;

	if (NT_SUCCESS(status))
	{
		MDAL_CloseHandle32(tokenHandle);
		return status;
	}

	// privilege missing
	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
	{
		MDAL_CloseHandle32(tokenHandle);
		return STATUS_UNSUCCESSFUL;
	}

	MDAL_CloseHandle32(tokenHandle);
	return status;
}

MUNINN_API NTSTATUS MUNINN_CALL
MDAL_SetRemoteSeDebugPrivilege32(
	_In_ const HANDLE tokenHandle)
{
	// required: TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY
	if (!MDAL_IsValidHandle(tokenHandle))
		return STATUS_INVALID_HANDLE;

	LUID luid{};
	NTSTATUS status{ LookupPrivilegeValueW(
		nullptr,
		SE_DEBUG_NAME_W,
		&luid) ?
		STATUS_SUCCESS :
		STATUS_UNSUCCESSFUL };

	if (!NT_SUCCESS(status))
		return status;

	if (!MDAL_IsValidLuid(luid))
		return STATUS_UNSUCCESSFUL;

	TOKEN_PRIVILEGES privileges{};
	privileges.PrivilegeCount = 1;
	privileges.Privileges[0].Luid = luid;
	privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	status = AdjustTokenPrivileges(
		tokenHandle,
		FALSE,
		&privileges,
		sizeof(TOKEN_PRIVILEGES),
		nullptr,
		nullptr) ?
		STATUS_SUCCESS :
		STATUS_UNSUCCESSFUL;

	if (NT_SUCCESS(status))
		return status;

	// privilege missing
	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
		return STATUS_UNSUCCESSFUL;

	return status;
}

MUNINN_API NTSTATUS MUNINN_CALL
MDAL_SetThreadPriority32(_In_ const DWORD priorityClass)
{
	return SetPriorityClass(
		GetCurrentProcess(),
		priorityClass) ?
		STATUS_SUCCESS :
		STATUS_UNSUCCESSFUL;
}

MUNINN_API NTSTATUS MUNINN_CALL
MDAL_SetThreadSuspended32(_In_ const DWORD threadId)
{
	HANDLE threadHandle{ OpenThread(
		THREAD_SUSPEND_RESUME,
		FALSE,
		threadId) };

	if (!MDAL_IsValidHandle(threadHandle))
		return STATUS_INVALID_HANDLE;

	DWORD suspendCount{
	SuspendThread(threadHandle) };

	if (suspendCount == SUSPEND_THREAD_ERROR)
		return STATUS_UNSUCCESSFUL;

	MDAL_CloseHandle32(threadHandle);
	return STATUS_SUCCESS;
}

MUNINN_API NTSTATUS MUNINN_CALL
MDAL_SetThreadResumed32(_In_ const DWORD threadId)
{
	HANDLE threadHandle{ OpenThread(
		THREAD_SUSPEND_RESUME,
		FALSE,
		threadId) };

	if (!MDAL_IsValidHandle(threadHandle))
		return STATUS_INVALID_HANDLE;

	DWORD suspendCount{
	ResumeThread(threadHandle) };

	if (suspendCount == RESUME_THREAD_ERROR)
		return STATUS_UNSUCCESSFUL;

	MDAL_CloseHandle32(threadHandle);
	return STATUS_SUCCESS;
}

MUNINN_API NTSTATUS MUNINN_CALL
MDAL_GetThreadPriority32(
	_In_ const HANDLE threadHandle,
	_Out_ INT* const pThreadPriority)
{
	if (!MDAL_IsValidHandle(threadHandle))
		return STATUS_INVALID_PARAMETER_1;
	if (pThreadPriority == nullptr)
		return STATUS_INVALID_PARAMETER_2;

	SetLastError(ERROR_SUCCESS);
	*pThreadPriority
		= GetThreadPriority(threadHandle);

	if (*pThreadPriority == THREAD_PRIORITY_ERROR_RETURN &&
		GetLastError() != ERROR_SUCCESS)
		return STATUS_UNSUCCESSFUL;

	return STATUS_SUCCESS;
}

MUNINN_API NTSTATUS MUNINN_CALL
MDAL_GetTokenInfoBufferSize32(
	_In_ const HANDLE tokenHandle,
	_In_ const _TOKEN_INFORMATION_CLASS infoClass,
	_Out_ DWORD* const pRequiredSize)
{
	if (!MDAL_IsValidHandle(tokenHandle))
		return STATUS_INVALID_PARAMETER_1;
	if (pRequiredSize == nullptr)
		return STATUS_INVALID_PARAMETER_3;

	*pRequiredSize = 0ul;

	NTSTATUS status{ GetTokenInformation(
		tokenHandle,
		infoClass,
		nullptr,
		0,
		pRequiredSize) ?
		STATUS_SUCCESS :
		STATUS_UNSUCCESSFUL };

	if (!NT_SUCCESS(status))
	{
		if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
			return STATUS_BUFFER_TOO_SMALL;
		else return status;
	}

	return status;
}

MUNINN_API NTSTATUS MUNINN_CALL
MDAL_GetSeDebugPrivilege32(
	_In_ const HANDLE tokenHandle,
	_Out_ BOOL* const pIsSeDebugPrivilegeEnabled)
{
	if (!MDAL_IsValidHandle(tokenHandle))
		return STATUS_INVALID_PARAMETER_1;
	if (pIsSeDebugPrivilegeEnabled == nullptr)
		return STATUS_INVALID_PARAMETER_2;

	*pIsSeDebugPrivilegeEnabled = FALSE;

	DWORD requiredBufferSize{};
	NTSTATUS status{ MDAL_GetTokenInfoBufferSize32(
		tokenHandle,
		TokenPrivileges,
		&requiredBufferSize) };

	if (!NT_SUCCESS(status))
		return status;

	if (!requiredBufferSize)
		return STATUS_UNSUCCESSFUL;

	BYTE* privilegesBuffer{
		new BYTE[requiredBufferSize] };

	status = GetTokenInformation(
		tokenHandle,
		TokenPrivileges,
		privilegesBuffer,
		requiredBufferSize,
		&requiredBufferSize) ?
		STATUS_SUCCESS :
		STATUS_UNSUCCESSFUL;

	PTOKEN_PRIVILEGES pTokenPrivileges{
		reinterpret_cast<PTOKEN_PRIVILEGES>(privilegesBuffer) };

	LUID debugLuid{};
	status = LookupPrivilegeValueW(
		nullptr,
		SE_DEBUG_NAME_W,
		&debugLuid) ?
		STATUS_SUCCESS :
		STATUS_UNSUCCESSFUL;

	if (!NT_SUCCESS(status))
	{
		delete[] privilegesBuffer;
		return status;
	}

	if (!MDAL_IsValidLuid(debugLuid))
	{
		delete[] privilegesBuffer;
		return STATUS_UNSUCCESSFUL;
	}

	status = STATUS_NOT_FOUND;
	for (DWORD i{}; i < pTokenPrivileges->PrivilegeCount; ++i)
	{
		LUID_AND_ATTRIBUTES& laa{
			pTokenPrivileges->Privileges[i] };

		if (laa.Luid.LowPart == debugLuid.LowPart &&
			laa.Luid.HighPart == debugLuid.HighPart)
		{
			*pIsSeDebugPrivilegeEnabled =
				(laa.Attributes & SE_PRIVILEGE_ENABLED) != FALSE;

			status = STATUS_SUCCESS;
			break;
		}
	}

	delete[] privilegesBuffer;
	return status;
}

MUNINN_API NTSTATUS MUNINN_CALL
MDAL_GetProcessInformation32(
	_In_ const DWORD processId,
	_Out_ PROCESSENTRY32W* const pProcessEntry)
{
	if (!MDAL_IsValidProcessId(processId))
		return STATUS_INVALID_PARAMETER_1;
	if (pProcessEntry == nullptr)
		return STATUS_INVALID_PARAMETER_2;

	*pProcessEntry = {};

	HANDLE snapshotHandle{ CreateToolhelp32Snapshot(
		TH32CS_SNAPPROCESS,
		0) };

	if (!MDAL_IsValidHandle(snapshotHandle))
		return STATUS_INVALID_HANDLE;


	pProcessEntry->dwSize = sizeof(PROCESSENTRY32W);
	if (!Process32FirstW(snapshotHandle, pProcessEntry))
	{
		MDAL_CloseHandle32(snapshotHandle);
		return STATUS_UNSUCCESSFUL;
	}

	do
	{
		if (pProcessEntry->th32ProcessID == processId)
		{
			MDAL_CloseHandle32(snapshotHandle);
			return STATUS_SUCCESS;
		}
	} while (Process32NextW(snapshotHandle, pProcessEntry));

	MDAL_CloseHandle32(snapshotHandle);
	return STATUS_NOT_FOUND;
}

MUNINN_API NTSTATUS MUNINN_CALL
MDAL_GetImageFileName32(
	_In_ const HANDLE processHandle,
	_Out_writes_(bufferLength)
	WCHAR* const pBuffer,
	_In_ const DWORD bufferLength,
	_Out_ DWORD* const pCopiedLength) noexcept
{
	if (!MDAL_IsValidHandle(processHandle))
		return STATUS_INVALID_PARAMETER_1;
	if (pBuffer == nullptr)
		return STATUS_INVALID_PARAMETER_2;
	if (pCopiedLength == nullptr)
		return STATUS_INVALID_PARAMETER_4;

	*pBuffer = L'\0';
	*pCopiedLength = 0ul;

	DWORD length{ bufferLength };
	NTSTATUS status = QueryFullProcessImageNameW(
		processHandle,
		0ul,
		pBuffer,
		&length) ?
		STATUS_SUCCESS :
		STATUS_UNSUCCESSFUL;

	if (!NT_SUCCESS(status))
		return status;

	*pCopiedLength = length;
	return STATUS_SUCCESS;
}

MUNINN_API NTSTATUS MUNINN_CALL
MDAL_GetModuleBaseAddress32(
	_In_ const DWORD processId,
	_In_ const wchar_t* const pModuleName,
	_Out_ uintptr_t* const pModuleBaseAddress)
{
	if (!MDAL_IsValidProcessId(processId))
		return STATUS_INVALID_PARAMETER_1;
	if (pModuleName == nullptr)
		return STATUS_INVALID_PARAMETER_2;
	if (pModuleBaseAddress == nullptr)
		return STATUS_INVALID_PARAMETER_3;

	*pModuleBaseAddress = 0ull;

	MODULEENTRY32W moduleEntry{};
	moduleEntry.dwSize = sizeof(MODULEENTRY32W);

	HANDLE snapshotHandle{ CreateToolhelp32Snapshot(
		TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
		processId) };

	if (!MDAL_IsValidHandle(snapshotHandle))
		return STATUS_INVALID_HANDLE;

	if (!Module32FirstW(snapshotHandle, &moduleEntry))
	{
		MDAL_CloseHandle32(snapshotHandle);
		return STATUS_UNSUCCESSFUL;
	}

	do
	{
		if (_wcsicmp(moduleEntry.szModule, pModuleName) == 0)
		{
			*pModuleBaseAddress
				= reinterpret_cast<uintptr_t>(moduleEntry.modBaseAddr);

			MDAL_CloseHandle32(snapshotHandle);
			return STATUS_SUCCESS;
		}
	} while (Module32NextW(snapshotHandle, &moduleEntry));

	MDAL_CloseHandle32(snapshotHandle);
	return STATUS_NOT_FOUND;
}

MUNINN_API NTSTATUS MUNINN_CALL
MDAL_GetWindowVisibility32(
	_In_ const DWORD processId,
	_Out_ BOOL* const pIsWindowVisible)
{
	if (!MDAL_IsValidProcessId(processId))
		return STATUS_INVALID_PARAMETER_1;
	if (pIsWindowVisible == nullptr)
		return STATUS_INVALID_PARAMETER_2;

	*pIsWindowVisible = FALSE;

	for (HWND hwnd{ GetTopWindow(nullptr) }; hwnd; hwnd = GetNextWindow(hwnd, GW_HWNDNEXT))
	{
		DWORD windowThreadProcessId{};
		GetWindowThreadProcessId(hwnd, &windowThreadProcessId);

		if (windowThreadProcessId == processId && IsWindowVisible(hwnd))
		{
			*pIsWindowVisible = TRUE;
			return STATUS_SUCCESS;
		}
	}

	return STATUS_NOT_FOUND;
}

MUNINN_API NTSTATUS MUNINN_CALL
MDAL_GetProcessArchitecture32(
	_In_ const HANDLE processHandle,
	_Out_ USHORT* const pProcessMachine,
	_Out_ USHORT* const pNativeMachine,
	_Out_ BOOL* const pIsWow64)
{
	if (!MDAL_IsValidHandle(processHandle))
		return STATUS_INVALID_PARAMETER_1;
	if (pProcessMachine == nullptr)
		return STATUS_INVALID_PARAMETER_2;
	if (pNativeMachine == nullptr)
		return STATUS_INVALID_PARAMETER_3;
	if (pIsWow64 == nullptr)
		return STATUS_INVALID_PARAMETER_4;

	*pProcessMachine = IMAGE_FILE_MACHINE_UNKNOWN;
	*pNativeMachine = IMAGE_FILE_MACHINE_UNKNOWN;
	*pIsWow64 = FALSE;

	NTSTATUS status{ IsWow64Process2(
		processHandle,
		// IMAGE_FILE_MACHINE_UNKNOWN if not a WOW64 process
		pProcessMachine,
		// Native architecture of host system
		pNativeMachine) ?
		STATUS_SUCCESS :
		STATUS_UNSUCCESSFUL };

	if (!NT_SUCCESS(status))
		return status;

	*pIsWow64
		= *pProcessMachine != IMAGE_FILE_MACHINE_UNKNOWN;

	// If running under WOW64, processMachine already contains the guest architecture.
	// Otherwise processMachine is IMAGE_FILE_MACHINE_UNKNOWN, so use the native machine.
	*pProcessMachine = *pIsWow64 ?
		*pProcessMachine :
		*pNativeMachine;

	return STATUS_SUCCESS;
}

MUNINN_API NTSTATUS MUNINN_CALL
MDAL_GetProcessModules32(
	_In_ const HANDLE processHandle,
	_In_ const DWORD processId,
	_Out_writes_(bufferLength)
	MODULEENTRY32W* const pBuffer,
	_In_ const DWORD bufferLength,
	_Out_ DWORD* const pCopiedLength)
{
	if (!MDAL_IsValidHandle(processHandle))
		return STATUS_INVALID_PARAMETER_1;
	if (!MDAL_IsValidProcessId(processId))
		return STATUS_INVALID_PARAMETER_2;
	if (pBuffer == nullptr)
		return STATUS_INVALID_PARAMETER_3;
	if (bufferLength == 0ul)
		return STATUS_BUFFER_TOO_SMALL;
	if (pCopiedLength == nullptr)
		return STATUS_INVALID_PARAMETER_5;

	*pBuffer = {};
	*pCopiedLength = 0ul;

	HANDLE snapshotHandle{ CreateToolhelp32Snapshot(
		TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
		processId) };

	if (!MDAL_IsValidHandle(snapshotHandle))
		return STATUS_INVALID_HANDLE;

	MODULEENTRY32W moduleEntry{};
	moduleEntry.dwSize = sizeof(MODULEENTRY32W);

	NTSTATUS status{ Module32FirstW(
		snapshotHandle,
		&moduleEntry) ?
		STATUS_SUCCESS :
		STATUS_UNSUCCESSFUL };

	if (!NT_SUCCESS(status))
	{
		MDAL_CloseHandle32(snapshotHandle);
		return status;
	}

	DWORD count{};
	do
	{
		if (count >= bufferLength)
		{
			MDAL_CloseHandle32(snapshotHandle);
			*pCopiedLength = count;
			return STATUS_BUFFER_TOO_SMALL;
		}

		pBuffer[count++] = moduleEntry;

	} while (Module32NextW(snapshotHandle, &moduleEntry));

	MDAL_CloseHandle32(snapshotHandle);
	*pCopiedLength = count;
	return STATUS_SUCCESS;
}

MUNINN_API NTSTATUS MUNINN_CALL
MDAL_GetProcessThreads32(
	_In_ const HANDLE processHandle,
	_In_ const DWORD processId,
	_Out_writes_(bufferLength)
	THREADENTRY32* const pBuffer,
	_In_ const DWORD bufferLength,
	_Out_ DWORD* const pCopiedLength)
{
	if (!MDAL_IsValidHandle(processHandle))
		return STATUS_INVALID_PARAMETER_1;
	if (!MDAL_IsValidProcessId(processId))
		return STATUS_INVALID_PARAMETER_2;
	if (pBuffer == nullptr)
		return STATUS_INVALID_PARAMETER_3;
	if (bufferLength == 0ul)
		return STATUS_BUFFER_TOO_SMALL;
	if (pCopiedLength == nullptr)
		return STATUS_INVALID_PARAMETER_5;

	*pBuffer = {};
	*pCopiedLength = 0ul;

	// The processId parameter is technically ignored for TH32CS_SNAPTHREAD.
	HANDLE snapshotHandle{ CreateToolhelp32Snapshot(
		TH32CS_SNAPTHREAD,
		processId) };

	if (!MDAL_IsValidHandle(snapshotHandle))
		return STATUS_INVALID_HANDLE;

	THREADENTRY32 threadEntry{};
	threadEntry.dwSize = sizeof(THREADENTRY32);
	NTSTATUS status{ Thread32First(
		snapshotHandle,
		&threadEntry) ?
		STATUS_SUCCESS :
		STATUS_UNSUCCESSFUL };

	if (!NT_SUCCESS(status))
	{
		MDAL_CloseHandle32(snapshotHandle);
		return status;
	}

	DWORD count{};
	do
	{
		if (threadEntry.th32OwnerProcessID != processId)
			continue;

		if (count >= bufferLength)
		{
			MDAL_CloseHandle32(snapshotHandle);
			*pCopiedLength = count;
			return STATUS_BUFFER_TOO_SMALL;
		}

		pBuffer[count++] = threadEntry;

	} while (Thread32Next(snapshotHandle, &threadEntry));

	MDAL_CloseHandle32(snapshotHandle);
	*pCopiedLength = count;
	return STATUS_SUCCESS;
}

MUNINN_API NTSTATUS MUNINN_CALL
MDAL_GetProcessHandles32(
	_In_ const HANDLE processHandle,
	_In_ const DWORD processId,
	_Out_writes_(bufferLength)
	PSS_HANDLE_ENTRY* const pBuffer,
	_In_ const DWORD bufferLength,
	_Out_ DWORD* const pCopiedLength) noexcept
{
	if (!MDAL_IsValidHandle(processHandle))
		return STATUS_INVALID_PARAMETER_1;
	if (!MDAL_IsValidProcessId(processId))
		return STATUS_INVALID_PARAMETER_2;
	if (pBuffer == nullptr)
		return STATUS_INVALID_PARAMETER_3;
	if (bufferLength == 0ul)
		return STATUS_BUFFER_TOO_SMALL;
	if (pCopiedLength == nullptr)
		return STATUS_INVALID_PARAMETER_5;

	*pBuffer = {};
	*pCopiedLength = 0ul;

	HPSS pssSnapshotHandle{};
	if (PssCaptureSnapshot(
		processHandle,
		PSS_CAPTURE_HANDLES |
		PSS_CAPTURE_HANDLE_NAME_INFORMATION |
		PSS_CAPTURE_HANDLE_BASIC_INFORMATION |
		PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION |
		PSS_CAPTURE_HANDLE_TRACE,
		0,
		&pssSnapshotHandle)
		!= ERROR_SUCCESS)
		return STATUS_UNSUCCESSFUL;

	HPSSWALK walkMarkerHandle{};
	if (PssWalkMarkerCreate(nullptr, &walkMarkerHandle)
		!= ERROR_SUCCESS)
	{
		PssFreeSnapshot(GetCurrentProcess(), pssSnapshotHandle);
		return STATUS_UNSUCCESSFUL;
	}

	DWORD count{};
	while (true)
	{
		PSS_HANDLE_ENTRY handleEntry{};
		DWORD walkStatus{ PssWalkSnapshot(
			pssSnapshotHandle,
			PSS_WALK_HANDLES,
			walkMarkerHandle,
			&handleEntry,
			sizeof(handleEntry)) };

		if (walkStatus == ERROR_NO_MORE_ITEMS)
			break;
		if (walkStatus != ERROR_SUCCESS)
			break;

		if (count >= bufferLength)
		{
			*pCopiedLength = count;
			PssWalkMarkerFree(walkMarkerHandle);
			PssFreeSnapshot(GetCurrentProcess(), pssSnapshotHandle);
			return STATUS_BUFFER_TOO_SMALL;
		}

		pBuffer[count++] = handleEntry;
	}

	*pCopiedLength = count;
	PssWalkMarkerFree(walkMarkerHandle);
	PssFreeSnapshot(GetCurrentProcess(), pssSnapshotHandle);
	return STATUS_SUCCESS;
}