#include "WindowsInjectionProvider.h"
#include "WindowsProcessProvider.h"
#include "WindowsUtilityProvider.h"

#ifndef WAIT_TIME
#define WAIT_TIME 5000ul // Expressed in milliseconds
#endif // !WAIT_TIME

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_RemoteLoadLibraryA(
	_In_ const HANDLE processHandle,
	_In_ LPCSTR const dllPath,
	_Out_ HMODULE* pModuleHandle)
{
	if (!DAL_IsValidHandle(processHandle))
		return STATUS_INVALID_PARAMETER_1;
	if (dllPath == NULL)
		return STATUS_INVALID_PARAMETER_2;
	if (pModuleHandle == NULL)
		return STATUS_INVALID_PARAMETER_3;

	SIZE_T size =
		(strlen(dllPath) + 1) * // Ensures null-termination
		sizeof(CHAR);

	// Allocate memory inside the remote process
	void* location = VirtualAllocEx(
		processHandle,
		NULL,
		size,
		MEM_COMMIT | MEM_RESERVE, // Commit and reserve memory.
		PAGE_READWRITE);

	if (location == NULL)
		return STATUS_NO_MEMORY;

	NTSTATUS status = DAL_Win32_WriteVirtualMemory(
		processHandle,
		(uintptr_t)location,
		dllPath,
		size);

	if (!NT_SUCCESS(status))
	{
		VirtualFreeEx(
			processHandle,
			location,
			0ull,
			MEM_RELEASE);

		return status;
	}

	HANDLE threadHandle = CreateRemoteThread(
		processHandle,
		NULL,
		0ull,
		(LPTHREAD_START_ROUTINE)LoadLibraryA, // StartAddress
		location, // Pointer to the remote DLL path string
		0ul,
		NULL);

	if (!DAL_IsValidHandle(threadHandle))
	{
		VirtualFreeEx(
			processHandle,
			location,
			0ull,
			MEM_RELEASE);

		return STATUS_INVALID_HANDLE;
	}

	// Wait until the thread finishes.
	WaitForSingleObject(threadHandle, WAIT_TIME);

	DWORD exitCode = 0ul;

	status = GetExitCodeThread(
		threadHandle,
		&exitCode) == TRUE ?
		STATUS_SUCCESS :
		STATUS_UNSUCCESSFUL;

	if (!NT_SUCCESS(status))
	{
		DAL_CloseHandle32(threadHandle);

		VirtualFreeEx(
			processHandle,
			location,
			0ull,
			MEM_RELEASE);

		return status;
	}

	// Cleanup
	DAL_CloseHandle32(threadHandle);
	VirtualFreeEx(
		processHandle,
		location,
		0ull,
		MEM_RELEASE);

	if (exitCode == 0ul)
	{
		*pModuleHandle = NULL;
		return STATUS_UNSUCCESSFUL;
	}

	*pModuleHandle = (HMODULE)exitCode;
	return STATUS_SUCCESS;
}

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_RemoteLoadLibraryW32(
	_In_ const HANDLE processHandle,
	_In_ LPWSTR const dllPath,
	_Out_ HMODULE* pModuleHandle)
{
	if (!DAL_IsValidHandle(processHandle))
		return STATUS_INVALID_PARAMETER_1;
	if (dllPath == NULL)
		return STATUS_INVALID_PARAMETER_2;
	if (pModuleHandle == NULL)
		return STATUS_INVALID_PARAMETER_3;

	SIZE_T size =
		(wcslen(dllPath) + 1) * // Ensures null-termination
		sizeof(WCHAR);

	// Allocate memory inside the remote process
	void* location = VirtualAllocEx(
		processHandle,
		NULL,
		size,
		MEM_COMMIT | MEM_RESERVE, // Commit and reserve memory.
		PAGE_READWRITE);

	if (location == NULL)
		return STATUS_NO_MEMORY;

	NTSTATUS status = DAL_Win32_WriteVirtualMemory(
		processHandle,
		(uintptr_t)location,
		dllPath,
		size);

	if (!NT_SUCCESS(status))
	{
		VirtualFreeEx(
			processHandle,
			location,
			0ull,
			MEM_RELEASE);

		return status;
	}

	HANDLE threadHandle = CreateRemoteThread(
		processHandle,
		NULL,
		0ull,
		(LPTHREAD_START_ROUTINE)LoadLibraryW, // StartAddress
		location, // Pointer to the remote DLL path string
		0ul,
		NULL);

	if (!DAL_IsValidHandle(threadHandle))
	{
		VirtualFreeEx(
			processHandle,
			location,
			0ull,
			MEM_RELEASE);

		return STATUS_INVALID_HANDLE;
	}

	// Wait for injection
	WaitForSingleObject(threadHandle, INFINITE);

	DWORD exitCode = 0ul;

	status = GetExitCodeThread(
		threadHandle,
		&exitCode) == TRUE ?
		STATUS_SUCCESS :
		STATUS_UNSUCCESSFUL;

	if (!NT_SUCCESS(status))
	{
		DAL_CloseHandle32(threadHandle);

		VirtualFreeEx(
			processHandle,
			location,
			0ull,
			MEM_RELEASE);

		return status;
	}

	// Cleanup
	DAL_CloseHandle32(threadHandle);
	VirtualFreeEx(
		processHandle,
		location,
		0ull,
		MEM_RELEASE);

	if (exitCode == 0ul)
	{
		*pModuleHandle = NULL;
		return STATUS_UNSUCCESSFUL;
	}

	*pModuleHandle = (HMODULE)exitCode;
	return STATUS_SUCCESS;
}