#ifndef WINDOWS_INJECTION_PROVIDER_H
#define WINDOWS_INJECTION_PROVIDER_H

#include "MuninnConfig.h"

#ifndef NTSTATUS
#define NTSTATUS LONG
#endif // !NTSTATUS

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_RemoteLoadLibraryA(
	_In_ const HANDLE processHandle,
	_In_ LPCSTR const dllPath,
	_Out_ HMODULE* pModuleHandle);

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_RemoteLoadLibraryW32(
	_In_ const HANDLE processHandle,
	_In_ LPWSTR const dllPath,
	_Out_ HMODULE* pModuleHandle);

#endif // !WINDOWS_INJECTION_PROVIDER_H