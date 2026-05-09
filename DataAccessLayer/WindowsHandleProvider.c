#include "WindowsHandleProvider.h"
#include "WindowsUtilityProvider.h"

#ifndef NT_CURRENT_PROCESS
#define NT_CURRENT_PROCESS ((HANDLE)(LONG_PTR)-1)
#endif // !NT_CURRENT_PROCESS

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_OpenProcessHandle(
	_In_ const DWORD processId,
	_In_ const ACCESS_MASK accessMask,
	_Out_ HANDLE* const pHandle)
{
	if (!DAL_IsValidProcessId(processId))
		return STATUS_INVALID_PARAMETER_1;
	if (pHandle == NULL)
		return STATUS_INVALID_PARAMETER_3;

	*pHandle = OpenProcess(
		accessMask,
		FALSE,
		processId);

	if (!DAL_IsValidHandle(*pHandle))
		return STATUS_INVALID_HANDLE;

	return STATUS_SUCCESS;
}

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_OpenProcessHandle(
	_In_ const DWORD processId,
	_In_ const ACCESS_MASK accessMask,
	_Out_ HANDLE* const pHandle)
{
	if (!DAL_IsValidProcessId(processId))
		return STATUS_INVALID_PARAMETER_1;
	if (pHandle == NULL)
		return STATUS_INVALID_PARAMETER_3;

	*pHandle = NULL;

	OBJECT_ATTRIBUTES objectAttributes = { 0 };
	objectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);

	CLIENT_ID clientId = { NULL, NULL };
	clientId.UniqueProcess = (HANDLE)(uintptr_t)processId;
	clientId.UniqueThread = NULL;

	NTSTATUS status = NtOpenProcess(
		pHandle,
		accessMask,
		&objectAttributes,
		&clientId);

	if (!DAL_IsValidHandle(*pHandle))
		*pHandle = NULL;

	return status;
}

MUNINN_API NTSTATUS MUNINN_CALL
DAL_CloseHandle32(_In_ const HANDLE handle)
{
	if (!DAL_IsValidHandle(handle))
		return STATUS_INVALID_PARAMETER_1;

	return CloseHandle(handle) ?
		STATUS_SUCCESS :
		STATUS_UNSUCCESSFUL;
}

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_CloseHandle(_In_ const HANDLE handle)
{
	if (!DAL_IsValidHandle(handle))
		return STATUS_INVALID_PARAMETER_1;

	return NtClose(handle);
}

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_DuplicateHandle(
	_In_ const HANDLE sourceHandle,
	_In_ const DWORD processId,
	_Out_ HANDLE* const pDuplicatedHandle)
{
	if (!DAL_IsValidHandle(sourceHandle))
		return STATUS_INVALID_PARAMETER_1;
	if (!DAL_IsValidProcessId(processId))
		return STATUS_INVALID_PARAMETER_2;
	if (pDuplicatedHandle == NULL)
		return STATUS_INVALID_PARAMETER_3;

	*pDuplicatedHandle = NULL;

	// Prefer explicity over InitializeObjectAttributes(p, n, a, r, s)
	OBJECT_ATTRIBUTES objectAttributes = { 0 };
	objectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
	objectAttributes.ObjectName = NULL;
	objectAttributes.Attributes = 0ul;
	objectAttributes.RootDirectory = NULL;
	objectAttributes.SecurityDescriptor = NULL;
	objectAttributes.SecurityQualityOfService = NULL;

	CLIENT_ID clientId = { NULL, NULL };
	clientId.UniqueProcess = (HANDLE)(uintptr_t)(processId);
	clientId.UniqueThread = NULL;

	HANDLE remoteProcessHandle = NULL;
	NTSTATUS status = NtOpenProcess(
		&remoteProcessHandle,
		PROCESS_DUP_HANDLE,
		&objectAttributes,
		&clientId);
	if (!NT_SUCCESS(status)) return status;

	HANDLE duplicatedHandle = NULL;
	status = NtDuplicateObject(
		remoteProcessHandle,
		sourceHandle,
		NT_CURRENT_PROCESS,
		pDuplicatedHandle,
		0ul,
		0ul,
		DUPLICATE_SAME_ACCESS);
	DAL_Nt_CloseHandle(remoteProcessHandle);

	if (!NT_SUCCESS(status))
		*pDuplicatedHandle = NULL;

	return status;
}

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_OpenTokenHandle(
	_In_ const HANDLE processHandle,
	_In_ const ACCESS_MASK accessMask,
	_Out_ HANDLE* const pTokenHandle)
{
	if (!DAL_IsValidHandle(processHandle))
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
DAL_Nt_OpenTokenHandle(
	_In_ const HANDLE processHandle,
	_In_ const ACCESS_MASK accessMask,
	_Out_ HANDLE* const pTokenHandle)
{
	if (!DAL_IsValidHandle(processHandle))
		return STATUS_INVALID_PARAMETER_1;
	if (pTokenHandle == NULL)
		return STATUS_INVALID_PARAMETER_3;

	*pTokenHandle = NULL;

	NTSTATUS status = NtOpenProcessToken(
		processHandle,
		accessMask,
		pTokenHandle);

	if (!NT_SUCCESS(status))
		*pTokenHandle = NULL;

	return status;
}