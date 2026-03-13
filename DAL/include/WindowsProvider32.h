#ifndef MUNINN_DATA_WINDOWS_PROVIDER_32
#define MUNINN_DATA_WINDOWS_PROVIDER_32

#include "ApiConfig.h"
#include "../phnt/phnt_windows.h"
#include <TlHelp32.h>
#include <ProcessSnapshot.h>

#ifndef NTSTATUS
#define NTSTATUS LONG
#endif // !NTSTATUS

MUNINN_API NTSTATUS MUNINN_CALL
MDAL_OpenProcessHandle32(
	_In_ const DWORD processId,
	_In_ const ACCESS_MASK accessMask,
	_Out_ HANDLE* const pHandle);

MUNINN_API NTSTATUS MUNINN_CALL
MDAL_CloseHandle32(_In_ const HANDLE handle);

MUNINN_API NTSTATUS MUNINN_CALL
MDAL_OpenTokenHandle32(
	_In_ const HANDLE processHandle,
	_In_ const ACCESS_MASK accessMask,
	_Out_ HANDLE* const pTokenHandle);

MUNINN_API NTSTATUS MUNINN_CALL
MDAL_SetSeDebugPrivilege32();

MUNINN_API NTSTATUS MUNINN_CALL
MDAL_SetRemoteSeDebugPrivilege32(
	_In_ const HANDLE tokenHandle);

MUNINN_API NTSTATUS MUNINN_CALL
MDAL_SetThreadPriority32(_In_ const DWORD priorityClass);

MUNINN_API NTSTATUS MUNINN_CALL
MDAL_SetThreadSuspended32(_In_ const DWORD threadId);

MUNINN_API NTSTATUS MUNINN_CALL
MDAL_SetThreadResumed32(_In_ const DWORD threadId);

MUNINN_API NTSTATUS MUNINN_CALL
MDAL_GetThreadPriority32(
	_In_ const HANDLE threadHandle,
	_Out_ INT* const pThreadPriority);

MUNINN_API NTSTATUS MUNINN_CALL
MDAL_GetTokenInfoBufferSize32(
	_In_ const HANDLE tokenHandle,
	_In_ const _TOKEN_INFORMATION_CLASS infoClass,
	_Out_ DWORD* const pRequiredSize);

MUNINN_API NTSTATUS MUNINN_CALL
MDAL_GetSeDebugPrivilege32(
	_In_ const HANDLE tokenHandle,
	_Out_ BOOL* const pIsSeDebugPrivilegeEnabled);

MUNINN_API NTSTATUS MUNINN_CALL
MDAL_GetProcessInformation32(
	_In_ const DWORD processId,
	_Out_ PROCESSENTRY32W* const pProcessEntry);

MUNINN_API NTSTATUS MUNINN_CALL
MDAL_GetImageFileName32(
	_In_ const HANDLE processHandle,
	_Out_writes_(bufferLength)
	WCHAR* const pBuffer,
	_In_ const DWORD bufferLength,
	_Out_ DWORD* const pCopiedLength);

MUNINN_API NTSTATUS MUNINN_CALL
MDAL_GetModuleBaseAddress32(
	_In_ const DWORD processId,
	_In_ const wchar_t* const pModuleName,
	_Out_ uintptr_t* const pModuleBaseAddress);

MUNINN_API NTSTATUS MUNINN_CALL
MDAL_GetWindowVisibility32(
	_In_ const DWORD processId,
	_Out_ BOOL* const pIsWindowVisible);

MUNINN_API NTSTATUS MUNINN_CALL
MDAL_GetProcessArchitecture32(
	_In_ const HANDLE processHandle,
	_Out_ USHORT* const pProcessMachine,
	_Out_ USHORT* const pNativeMachine,
	_Out_ BOOL* const pIsWow64);

MUNINN_API NTSTATUS MUNINN_CALL
MDAL_GetProcessModules32(
	_In_ const HANDLE processHandle,
	_In_ const DWORD processId,
	_Out_writes_(bufferLength)
	MODULEENTRY32W* const pBuffer,
	_In_ const DWORD bufferLength,
	_Out_ DWORD* const pCopiedLength);

MUNINN_API NTSTATUS MUNINN_CALL
MDAL_GetProcessThreads32(
	_In_ const HANDLE processHandle,
	_In_ const DWORD processId,
	_Out_writes_(bufferLength)
	THREADENTRY32* const pBuffer,
	_In_ const DWORD bufferLength,
	_Out_ DWORD* const pCopiedLength);

MUNINN_API NTSTATUS MUNINN_CALL
MDAL_GetProcessHandles32(
	_In_ const HANDLE processHandle,
	_In_ const DWORD processId,
	_Out_writes_(bufferLength)
	PSS_HANDLE_ENTRY* const pBuffer,
	_In_ const DWORD bufferLength,
	_Out_ DWORD* const pCopiedLength);
#endif // !MUNINN_DATA_WINDOWS_PROVIDER_32