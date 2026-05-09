#include "WindowsProcessProvider.h"
#include "WindowsUtilityProvider.h"

#ifndef PREALLOC_HANDLES
#define PREALLOC_HANDLES 1000
#endif // !PREALLOC_HANDLES

#ifndef MAX_PATH_LONG
#define MAX_PATH_LONG 32768
#endif // !MAX_PATH_LONG

#ifndef QSI_MIN_BUFFER_SIZE 
#define QSI_MIN_BUFFER_SIZE 0x20
#endif // !QSI_MIN_BUFFER_SIZE 

#ifndef _MAX_PATH
#define _MAX_PATH 260
#endif // !_MAX_PATH

#ifndef MAX_PATH
#define MAX_PATH _MAX_PATH
#endif // !MAX_PATH

#ifndef MAX_MODULES
#define MAX_MODULES 1024
#endif // !MAX_MODULES

#ifndef PAGE_SIZE
#define PAGE_SIZE 0x1000
#endif // !PAGE_SIZE

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_GetQSIBufferSize(
	_In_ const SYSTEM_INFORMATION_CLASS infoClass,
	_Out_ DWORD* const pRequiredBufferSize)
{
	if (pRequiredBufferSize == NULL)
		return STATUS_INVALID_PARAMETER_2;

	*pRequiredBufferSize = 0ul;

	BYTE buffer[QSI_MIN_BUFFER_SIZE] = { 0 };
	NTSTATUS status = NtQuerySystemInformation(
		infoClass,
		buffer,
		sizeof(buffer),
		pRequiredBufferSize);

	if (status != STATUS_INFO_LENGTH_MISMATCH)
		*pRequiredBufferSize = 0ul;

	return status;
}

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_GetQOBufferSize(
	_In_ const HANDLE duplicatedHandle,
	_In_ const OBJECT_INFORMATION_CLASS infoClass,
	_Out_ DWORD* const pRequiredBufferSize)
{
	if (!DAL_IsValidHandle(duplicatedHandle))
		return STATUS_INVALID_PARAMETER_1;
	if (pRequiredBufferSize == NULL)
		return STATUS_INVALID_PARAMETER_3;

	*pRequiredBufferSize = 0ul;

	NTSTATUS status = NtQueryObject(
		duplicatedHandle,
		infoClass,
		NULL,
		0ul,
		pRequiredBufferSize);

	if (status != STATUS_INFO_LENGTH_MISMATCH)
		*pRequiredBufferSize = 0ul;

	return status;
}

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_GetObjectName(
	_In_ const HANDLE sourceHandle,
	_In_ const DWORD processId,
	_Out_writes_(bufferLength)
	WCHAR* const pBuffer,
	_In_ const DWORD bufferLength,
	_Out_ DWORD* const pCopiedLength)
{
	if (!DAL_IsValidHandle(sourceHandle))
		return STATUS_INVALID_PARAMETER_1;
	if (!DAL_IsValidProcessId(processId))
		return STATUS_INVALID_PARAMETER_2;
	if (pBuffer == NULL)
		return STATUS_INVALID_PARAMETER_3;
	if (bufferLength == 0ul)
		return STATUS_BUFFER_TOO_SMALL;
	if (pCopiedLength == NULL)
		return STATUS_INVALID_PARAMETER_5;

	memset(
		pBuffer,
		0,
		bufferLength * sizeof(WCHAR));

	*pCopiedLength = 0ul;

	HANDLE duplicatedHandle = NULL;
	NTSTATUS status = DAL_Nt_DuplicateHandle(
		sourceHandle,
		processId,
		&duplicatedHandle);

	if (!NT_SUCCESS(status))
		return status;

	if (!DAL_IsValidHandle(duplicatedHandle))
		return STATUS_INVALID_HANDLE;

	DWORD requiredBufferSize = 0ul;
	status = DAL_Nt_GetQOBufferSize(
		duplicatedHandle,
		ObjectNameInformation,
		&requiredBufferSize);

	if (status != STATUS_INFO_LENGTH_MISMATCH &&
		!NT_SUCCESS(status))
	{
		DAL_Nt_CloseHandle(duplicatedHandle);
		return status;
	}

	if (!requiredBufferSize)
	{
		DAL_Nt_CloseHandle(duplicatedHandle);
		return STATUS_UNSUCCESSFUL;
	}

	BYTE* nameInfoBuffer =
		(BYTE*)malloc(requiredBufferSize);
	if (nameInfoBuffer == NULL)
		return STATUS_NO_MEMORY;

	status = NtQueryObject(
		duplicatedHandle,
		ObjectNameInformation,
		nameInfoBuffer,
		requiredBufferSize,
		NULL);

	if (!NT_SUCCESS(status))
	{
		free(nameInfoBuffer);
		DAL_Nt_CloseHandle(duplicatedHandle);
		return status;
	}

	OBJECT_NAME_INFORMATION* nameInfo =
		(OBJECT_NAME_INFORMATION*)(nameInfoBuffer);

	if (nameInfo->Name.Buffer &&
		nameInfo->Name.Length > 0)
	{
		DWORD charsToCopy =
			nameInfo->Name.Length / sizeof(WCHAR);

		// leave room for null terminator -> (-1ul)
		if (charsToCopy >= bufferLength)
			charsToCopy = bufferLength - 1ul;

		for (DWORD i = 0ul; i < charsToCopy; ++i)
			pBuffer[i] = nameInfo->Name.Buffer[i];

		pBuffer[charsToCopy] = L'\0';
		*pCopiedLength = charsToCopy;
	}

	free(nameInfoBuffer);
	DAL_Nt_CloseHandle(duplicatedHandle);
	return STATUS_SUCCESS;
}

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_GetObjectType(
	_In_ const HANDLE sourceHandle,
	_In_ const DWORD processId,
	_Out_writes_(bufferLength)
	WCHAR* const pBuffer,
	_In_ const DWORD bufferLength,
	_Out_ DWORD* const pCopiedLength)
{
	if (!DAL_IsValidHandle(sourceHandle))
		return STATUS_INVALID_PARAMETER_1;
	if (!DAL_IsValidProcessId(processId))
		return STATUS_INVALID_PARAMETER_2;
	if (pBuffer == NULL)
		return STATUS_INVALID_PARAMETER_3;
	if (bufferLength == 0ul)
		return STATUS_BUFFER_TOO_SMALL;
	if (pCopiedLength == NULL)
		return STATUS_INVALID_PARAMETER_5;

	memset(
		pBuffer,
		0,
		bufferLength * sizeof(WCHAR));

	*pCopiedLength = 0ul;

	HANDLE duplicatedHandle = NULL;
	NTSTATUS status = DAL_Nt_DuplicateHandle(
		sourceHandle,
		processId,
		&duplicatedHandle);

	if (!NT_SUCCESS(status))
		return status;

	if (!DAL_IsValidHandle(duplicatedHandle))
		return STATUS_INVALID_HANDLE;

	DWORD requiredBufferSize = 0ul;
	status = DAL_Nt_GetQOBufferSize(
		duplicatedHandle,
		ObjectTypeInformation,
		&requiredBufferSize);

	if (status != STATUS_INFO_LENGTH_MISMATCH &&
		!NT_SUCCESS(status))
	{
		DAL_Nt_CloseHandle(duplicatedHandle);
		return status;
	}

	if (!requiredBufferSize)
	{
		DAL_Nt_CloseHandle(duplicatedHandle);
		return STATUS_UNSUCCESSFUL;
	}

	BYTE* typeInfoBuffer =
		(BYTE*)malloc(requiredBufferSize);
	if (typeInfoBuffer == NULL)
		return STATUS_NO_MEMORY;

	status = NtQueryObject(
		duplicatedHandle,
		ObjectTypeInformation,
		typeInfoBuffer,
		requiredBufferSize,
		NULL);

	if (!NT_SUCCESS(status))
	{
		free(typeInfoBuffer);
		DAL_Nt_CloseHandle(duplicatedHandle);
		return status;
	}

	OBJECT_TYPE_INFORMATION* typeInfo =
		(OBJECT_TYPE_INFORMATION*)typeInfoBuffer;

	if (typeInfo->TypeName.Buffer &&
		typeInfo->TypeName.Length > 0)
	{
		DWORD charsToCopy =
			typeInfo->TypeName.Length / sizeof(WCHAR);

		// leave room for null terminator -> (-1ul)
		if (charsToCopy >= bufferLength)
			charsToCopy = bufferLength - 1ul;

		for (DWORD i = 0ul; i < charsToCopy; ++i)
			pBuffer[i] = typeInfo->TypeName.Buffer[i];

		pBuffer[charsToCopy] = L'\0';
		*pCopiedLength = charsToCopy;
	}

	free(typeInfoBuffer);
	DAL_Nt_CloseHandle(duplicatedHandle);
	return STATUS_SUCCESS;
}

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_GetRemoteUnicodeString(
	_In_ const HANDLE processHandle,
	_In_ const UNICODE_STRING* const pRemoteUnicodeString,
	_Out_writes_(bufferLength)
	WCHAR* const pBuffer,
	_In_ const DWORD bufferLength,
	_Out_ DWORD* const pCopiedLength)
{
	if (!DAL_IsValidHandle(processHandle))
		return STATUS_INVALID_PARAMETER_1;
	if (pRemoteUnicodeString == NULL)
		return STATUS_INVALID_PARAMETER_2;
	if (pBuffer == NULL)
		return STATUS_INVALID_PARAMETER_3;
	if (bufferLength == 0ul)
		return STATUS_BUFFER_TOO_SMALL;
	if (pCopiedLength == NULL)
		return STATUS_INVALID_PARAMETER_5;

	memset(
		pBuffer,
		0,
		bufferLength * sizeof(WCHAR));

	*pCopiedLength = 0ul;

	NTSTATUS status = DAL_Nt_ReadVirtualMemory(
		processHandle,
		(uintptr_t)pRemoteUnicodeString->Buffer,
		pBuffer,
		pRemoteUnicodeString->Length);

	*pCopiedLength = pRemoteUnicodeString->Length / sizeof(WCHAR);
	return status;
}

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_GetProcessId(
	_In_ const WCHAR* const processName,
	_Out_ DWORD* const pProcessId,
	_Out_ BOOL* const pIsRunning)
{
	if (processName == NULL)
		return STATUS_INVALID_PARAMETER_1;
	if (pProcessId == NULL)
		return STATUS_INVALID_PARAMETER_2;
	if (pIsRunning == NULL)
		return STATUS_INVALID_PARAMETER_3;

	*pProcessId = 0ul;
	*pIsRunning = FALSE;

	PROCESSENTRY32W pEntry32W = { 0 };
	pEntry32W.dwSize = sizeof(pEntry32W);

	HANDLE hSnapshot = CreateToolhelp32Snapshot(
		TH32CS_SNAPPROCESS,
		0ul);

	if (!DAL_IsValidHandle(hSnapshot))
		return STATUS_INVALID_HANDLE;

	if (!Process32First(hSnapshot, &pEntry32W))
	{
		CloseHandle(hSnapshot);
		return STATUS_UNSUCCESSFUL;
	}

	do
	{
		// Case insensitive widestring comparison.
		if (_wcsicmp(pEntry32W.szExeFile, processName) == 0) {
			*pProcessId = pEntry32W.th32ProcessID;
			*pIsRunning = TRUE;
			break;
		}
	} while (Process32Next(hSnapshot, &pEntry32W));

	CloseHandle(hSnapshot);

	return (*pProcessId != 0ul) ?
		STATUS_SUCCESS :
		STATUS_NOT_FOUND;
}

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_GetProcessInformation(
	_In_ const DWORD processId,
	_Out_ PROCESSENTRY32W* const pProcessEntry)
{
	if (!DAL_IsValidProcessId(processId))
		return STATUS_INVALID_PARAMETER_1;
	if (pProcessEntry == NULL)
		return STATUS_INVALID_PARAMETER_2;

	memset(pProcessEntry, 0, sizeof(*pProcessEntry));
	pProcessEntry->dwSize = sizeof(PROCESSENTRY32W);

	HANDLE snapshotHandle = CreateToolhelp32Snapshot(
		TH32CS_SNAPPROCESS,
		0);

	if (!DAL_IsValidHandle(snapshotHandle))
		return STATUS_INVALID_HANDLE;

	if (!Process32FirstW(snapshotHandle, pProcessEntry))
	{
		DAL_CloseHandle32(snapshotHandle);
		return STATUS_UNSUCCESSFUL;
	}

	do
	{
		if (pProcessEntry->th32ProcessID == processId)
		{
			DAL_CloseHandle32(snapshotHandle);
			return STATUS_SUCCESS;
		}
	} while (Process32NextW(snapshotHandle, pProcessEntry));

	DAL_CloseHandle32(snapshotHandle);
	return STATUS_NOT_FOUND;
}

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_GetSystemProcessInformation(
	_Out_ BYTE** const ppBuffer,
	_Out_ DWORD* const pSize)
{
	if (ppBuffer == NULL)
		return STATUS_INVALID_PARAMETER_1;
	if (pSize == NULL)
		return STATUS_INVALID_PARAMETER_2;

	*ppBuffer = NULL;
	*pSize = 0ul;

	DWORD requiredBufferSize = 0ul;
	NTSTATUS status = DAL_Nt_GetQSIBufferSize(
		SystemProcessInformation,
		&requiredBufferSize);

	if (!requiredBufferSize)
		return STATUS_UNSUCCESSFUL;

	BYTE* systemInfoBuffer =
		(BYTE*)malloc(requiredBufferSize);
	if (systemInfoBuffer == NULL)
		return STATUS_NO_MEMORY;

	status = NtQuerySystemInformation(
		SystemProcessInformation,
		systemInfoBuffer,
		requiredBufferSize,
		NULL);

	if (!NT_SUCCESS(status))
	{
		free(systemInfoBuffer);
		return status;
	}

	*ppBuffer = systemInfoBuffer;
	*pSize = requiredBufferSize;

	return status;
}

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_GetProcessInformation(
	_In_ const HANDLE processHandle,
	_Out_ PROCESS_EXTENDED_BASIC_INFORMATION* const pProcessInfo)
{
	if (!DAL_IsValidHandle(processHandle))
		return STATUS_INVALID_PARAMETER_1;
	if (pProcessInfo == NULL)
		return STATUS_INVALID_PARAMETER_2;

	memset(
		pProcessInfo,
		0,
		sizeof(*pProcessInfo));

	NTSTATUS status = NtQueryInformationProcess(
		processHandle,
		ProcessBasicInformation,
		pProcessInfo,
		sizeof(PROCESS_EXTENDED_BASIC_INFORMATION),
		NULL);

	if (!NT_SUCCESS(status))
		memset(
			pProcessInfo,
			0,
			sizeof(*pProcessInfo));

	return status;
}

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_GetImageFileName(
	_In_ const HANDLE processHandle,
	_Out_writes_(bufferLength)
	WCHAR* const pBuffer,
	_In_ const DWORD bufferLength,
	_Out_ DWORD* const pCopiedLength)
{
	if (!DAL_IsValidHandle(processHandle))
		return STATUS_INVALID_PARAMETER_1;
	if (pBuffer == NULL)
		return STATUS_INVALID_PARAMETER_2;
	if (pCopiedLength == NULL)
		return STATUS_INVALID_PARAMETER_4;

	memset(pBuffer, 0, bufferLength * sizeof(WCHAR));
	*pCopiedLength = 0ul;

	DWORD length = bufferLength;
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
DAL_Nt_GetImageFileName(
	_In_ const HANDLE processHandle,
	_Out_writes_(bufferLength)
	WCHAR* const pBuffer,
	_In_ const DWORD bufferLength,
	_Out_ DWORD* const pCopiedLength)
{
	if (!DAL_IsValidHandle(processHandle))
		return STATUS_INVALID_PARAMETER_1;
	if (pBuffer == NULL)
		return STATUS_INVALID_PARAMETER_2;
	if (bufferLength == 0ul)
		return STATUS_BUFFER_TOO_SMALL;
	if (pCopiedLength == NULL)
		return STATUS_INVALID_PARAMETER_4;

	memset(
		pBuffer,
		0,
		bufferLength * sizeof(WCHAR));

	*pCopiedLength = 0ul;

	BYTE imageFileNameBuffer[MAX_PATH];
	memset(
		imageFileNameBuffer,
		0,
		sizeof(imageFileNameBuffer));

	NTSTATUS status = NtQueryInformationProcess(
		processHandle,
		ProcessImageFileName,
		imageFileNameBuffer,
		sizeof(imageFileNameBuffer),
		NULL);

	if (!NT_SUCCESS(status))
		return status;

	PUNICODE_STRING pImageFileName =
		(PUNICODE_STRING)imageFileNameBuffer;

	if (pImageFileName->Buffer &&
		pImageFileName->Length)
	{
		DWORD charsToCopy =
			pImageFileName->Length / sizeof(WCHAR);

		if (charsToCopy >= bufferLength)
			charsToCopy = bufferLength - 1ul;

		for (DWORD i = 0ul; i < charsToCopy; ++i)
			pBuffer[i] = pImageFileName->Buffer[i];

		pBuffer[charsToCopy] = L'\0';
		*pCopiedLength = charsToCopy;
	}

	return status;
}

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_GetWin32ImageFileName(
	_In_ const HANDLE processHandle,
	_Out_writes_(bufferLength)
	WCHAR* const pBuffer,
	_In_ const DWORD bufferLength,
	_Out_ DWORD* const pCopiedLength)
{
	if (!DAL_IsValidHandle(processHandle))
		return STATUS_INVALID_PARAMETER_1;
	if (pBuffer == NULL)
		return STATUS_INVALID_PARAMETER_2;
	if (bufferLength == 0ul)
		return STATUS_BUFFER_TOO_SMALL;
	if (pCopiedLength == NULL)
		return STATUS_INVALID_PARAMETER_4;

	memset(
		pBuffer,
		0,
		bufferLength * sizeof(WCHAR));

	*pCopiedLength = 0ul;

	BYTE imageFileNameBuffer[MAX_PATH];
	memset(
		imageFileNameBuffer,
		0,
		sizeof(imageFileNameBuffer));

	NTSTATUS status = NtQueryInformationProcess(
		processHandle,
		ProcessImageFileNameWin32,
		imageFileNameBuffer,
		sizeof(imageFileNameBuffer),
		NULL);

	if (!NT_SUCCESS(status))
		return status;

	PUNICODE_STRING pImageFileName =
		(PUNICODE_STRING)imageFileNameBuffer;

	if (pImageFileName->Buffer &&
		pImageFileName->Length)
	{
		DWORD charsToCopy =
			pImageFileName->Length / sizeof(WCHAR);

		if (charsToCopy >= bufferLength)
			charsToCopy = bufferLength - 1ul;

		for (DWORD i = 0ul; i < charsToCopy; ++i)
			pBuffer[i] = pImageFileName->Buffer[i];

		pBuffer[charsToCopy] = L'\0';
		*pCopiedLength = charsToCopy;
	}

	return status;
}

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_GetModuleBaseAddress(
	_In_ const DWORD processId,
	_In_ const wchar_t* const pModuleName,
	_Out_ uintptr_t* const pModuleBaseAddress)
{
	if (!DAL_IsValidProcessId(processId))
		return STATUS_INVALID_PARAMETER_1;
	if (pModuleName == NULL)
		return STATUS_INVALID_PARAMETER_2;
	if (pModuleBaseAddress == NULL)
		return STATUS_INVALID_PARAMETER_3;

	*pModuleBaseAddress = 0ull;

	MODULEENTRY32W moduleEntry = { 0 };
	moduleEntry.dwSize = sizeof(MODULEENTRY32W);

	HANDLE snapshotHandle = CreateToolhelp32Snapshot(
		TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
		processId);

	if (!DAL_IsValidHandle(snapshotHandle))
		return STATUS_INVALID_HANDLE;

	if (!Module32FirstW(snapshotHandle, &moduleEntry))
	{
		DAL_CloseHandle32(snapshotHandle);
		return STATUS_UNSUCCESSFUL;
	}

	do
	{
		if (_wcsicmp(moduleEntry.szModule, pModuleName) == 0)
		{
			*pModuleBaseAddress =
				(uintptr_t)(moduleEntry.modBaseAddr);

			DAL_CloseHandle32(snapshotHandle);
			return STATUS_SUCCESS;
		}
	} while (Module32NextW(snapshotHandle, &moduleEntry));

	DAL_CloseHandle32(snapshotHandle);
	return STATUS_NOT_FOUND;
}

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_GetPebBaseAddress(
	_In_ const HANDLE processHandle,
	_Out_ uintptr_t* const pPebBaseAddress)
{
	if (!DAL_IsValidHandle(processHandle))
		return STATUS_INVALID_PARAMETER_1;
	if (pPebBaseAddress == NULL)
		return STATUS_INVALID_PARAMETER_2;

	*pPebBaseAddress = 0ull;

	PROCESS_EXTENDED_BASIC_INFORMATION processInfo = { 0 };
	NTSTATUS status = DAL_Nt_GetProcessInformation(
		processHandle,
		&processInfo);

	if (!NT_SUCCESS(status))
		return status;

	*pPebBaseAddress =
		(uintptr_t)processInfo.BasicInfo.PebBaseAddress;

	if (!DAL_IsValidAddress(*pPebBaseAddress))
	{
		*pPebBaseAddress = 0ull;
		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_GetPebBaseAddressFromProcessInfo(
	_In_ const PROCESS_EXTENDED_BASIC_INFORMATION* const pProcessInfo,
	_Out_ uintptr_t* const pPebBaseAddress)
{
	if (pProcessInfo == NULL)
		return STATUS_INVALID_PARAMETER_2;
	if (pPebBaseAddress == NULL)
		return STATUS_INVALID_PARAMETER_2;

	*pPebBaseAddress =
		(uintptr_t)pProcessInfo->BasicInfo.PebBaseAddress;

	if (!DAL_IsValidAddress(*pPebBaseAddress))
	{
		*pPebBaseAddress = 0ull;
		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_GetPebBaseAddressAndProcessInfo(
	_In_ const HANDLE processHandle,
	_Out_ uintptr_t* const pPebBaseAddress,
	_Out_ PROCESS_EXTENDED_BASIC_INFORMATION* const pProcessInfo)
{
	if (!DAL_IsValidHandle(processHandle))
		return STATUS_INVALID_PARAMETER_1;
	if (pPebBaseAddress == NULL)
		return STATUS_INVALID_PARAMETER_2;
	if (pProcessInfo == NULL)
		return STATUS_INVALID_PARAMETER_3;

	*pPebBaseAddress = 0ull;

	memset(
		pProcessInfo,
		0,
		sizeof(*pProcessInfo));

	NTSTATUS status = DAL_Nt_GetProcessInformation(
		processHandle,
		pProcessInfo);

	if (!NT_SUCCESS(status))
		return status;

	*pPebBaseAddress =
		(uintptr_t)pProcessInfo->BasicInfo.PebBaseAddress;

	if (!DAL_IsValidAddress(*pPebBaseAddress))
	{
		*pPebBaseAddress = 0ull;

		memset(
			pProcessInfo,
			0,
			sizeof(*pProcessInfo));

		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_GetPeb(
	_In_ const HANDLE processHandle,
	_Out_ PEB* const pPeb)
{
	if (!DAL_IsValidHandle(processHandle))
		return STATUS_INVALID_PARAMETER_1;
	if (pPeb == NULL)
		return STATUS_INVALID_PARAMETER_2;

	memset(
		pPeb,
		0,
		sizeof(*pPeb));

	uintptr_t pebBaseAddress = 0ull;
	NTSTATUS status = DAL_Nt_GetPebBaseAddress(
		processHandle,
		&pebBaseAddress);

	if (!NT_SUCCESS(status))
		return status;

	if (!DAL_IsValidAddress(pebBaseAddress))
		return STATUS_INVALID_ADDRESS;

	status = DAL_Nt_ReadVirtualMemory(
		processHandle,
		pebBaseAddress,
		pPeb,
		sizeof(*pPeb));

	if (!NT_SUCCESS(status))
		memset(
			pPeb,
			0,
			sizeof(*pPeb));

	return status;
}

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_GetPebAndPebBaseAddress(
	_In_ const HANDLE processHandle,
	_Out_ uintptr_t* const pPebBaseAddress,
	_Out_ PEB* const pPeb)
{
	if (!DAL_IsValidHandle(processHandle))
		return STATUS_INVALID_PARAMETER_1;
	if (pPebBaseAddress == NULL)
		return STATUS_INVALID_PARAMETER_2;
	if (pPeb == NULL)
		return STATUS_INVALID_PARAMETER_3;

	*pPebBaseAddress = 0ull;

	memset(
		pPeb,
		0,
		sizeof(*pPeb));

	NTSTATUS status = DAL_Nt_GetPebBaseAddress(
		processHandle,
		pPebBaseAddress);

	if (!NT_SUCCESS(status))
		return status;

	status = DAL_Nt_ReadVirtualMemory(
		processHandle,
		*pPebBaseAddress,
		pPeb,
		sizeof(*pPeb));

	if (!NT_SUCCESS(status))
	{
		*pPebBaseAddress = 0ull;

		memset(
			pPeb,
			0,
			sizeof(*pPeb));
	}

	return status;
}

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_GetModuleBaseAddress(
	_In_ const HANDLE processHandle,
	_Out_ uintptr_t* const pModuleBaseAddress)
{
	if (!DAL_IsValidHandle(processHandle))
		return STATUS_INVALID_PARAMETER_1;
	if (pModuleBaseAddress == NULL)
		return STATUS_INVALID_PARAMETER_2;

	*pModuleBaseAddress = 0ull;

	uintptr_t pebBaseAddress = 0ull;
	PROCESS_EXTENDED_BASIC_INFORMATION processInfo = { 0 };
	NTSTATUS status = DAL_Nt_GetPebBaseAddressAndProcessInfo(
		processHandle,
		&pebBaseAddress,
		&processInfo);

	if (!NT_SUCCESS(status))
		return status;

	if (!DAL_IsValidAddress(pebBaseAddress))
		return STATUS_INVALID_ADDRESS;

	PEB peb = { 0 };
	status = DAL_Nt_ReadVirtualMemory(
		processHandle,
		pebBaseAddress,
		&peb,
		sizeof(peb));

	if (!NT_SUCCESS(status))
		return status;

	if (!peb.Ldr)
		return STATUS_UNSUCCESSFUL;

	uintptr_t loaderAddress =
		(uintptr_t)peb.Ldr;

	if (!DAL_IsValidAddress(loaderAddress))
		return STATUS_INVALID_ADDRESS;

	// Read loader data
	PEB_LDR_DATA loaderData = { 0 };
	status = DAL_Nt_ReadVirtualMemory(
		processHandle,
		loaderAddress,
		&loaderData,
		sizeof(loaderData));

	if (!NT_SUCCESS(status))
		return status;

	// First module in load order list
	uintptr_t firstLink =
		(uintptr_t)loaderData.InLoadOrderModuleList.Flink;

	if (!DAL_IsValidAddress(firstLink))
		return STATUS_INVALID_ADDRESS;

	// Get the LDR_DATA_TABLE_ENTRY
	uintptr_t entryAddress =
		firstLink - offsetof(LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
	LDR_DATA_TABLE_ENTRY entry = { 0 };
	status = DAL_Nt_ReadVirtualMemory(
		processHandle,
		entryAddress,
		&entry,
		sizeof(entry));

	if (entry.DllBase == NULL)
		return STATUS_UNSUCCESSFUL;

	*pModuleBaseAddress =
		(uintptr_t)entry.DllBase;

	return status;
}

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_GetModuleBaseAddressFromProcessInfo(
	_In_ const HANDLE processHandle,
	_In_ const PROCESS_EXTENDED_BASIC_INFORMATION* const processInfo,
	_Out_ uintptr_t* const pModuleBaseAddress)
{
	if (!DAL_IsValidHandle(processHandle))
		return STATUS_INVALID_PARAMETER_1;
	if (processInfo == NULL)
		return STATUS_INVALID_PARAMETER_2;
	if (pModuleBaseAddress == NULL)
		return STATUS_INVALID_PARAMETER_3;

	*pModuleBaseAddress = 0ull;

	uintptr_t pebBaseAddress =
		(uintptr_t)processInfo->BasicInfo.PebBaseAddress;

	if (!DAL_IsValidAddress(pebBaseAddress))
		return STATUS_INVALID_ADDRESS;

	PEB peb = { 0 };
	NTSTATUS status = DAL_Nt_ReadVirtualMemory(
		processHandle,
		pebBaseAddress,
		&peb,
		sizeof(peb));

	if (!NT_SUCCESS(status))
		return status;
	if (!peb.Ldr)
		return STATUS_UNSUCCESSFUL;

	uintptr_t loaderAddress =
		(uintptr_t)peb.Ldr;

	if (!DAL_IsValidAddress(loaderAddress))
		return STATUS_INVALID_ADDRESS;

	PEB_LDR_DATA loaderData = { 0 };
	status = DAL_Nt_ReadVirtualMemory(
		processHandle,
		loaderAddress,
		&loaderData,
		sizeof(PEB_LDR_DATA));

	if (!NT_SUCCESS(status))
		return status;

	uintptr_t firstLink =
		(uintptr_t)loaderData.InLoadOrderModuleList.Flink;

	if (!DAL_IsValidAddress(firstLink))
		return STATUS_INVALID_ADDRESS;

	uintptr_t entryAddress =
		firstLink - offsetof(LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

	LDR_DATA_TABLE_ENTRY entry = { 0 };
	status = DAL_Nt_ReadVirtualMemory(
		processHandle,
		entryAddress,
		&entry,
		sizeof(entry));

	if (!NT_SUCCESS(status))
		return status;
	if (entry.DllBase == NULL)
		return STATUS_UNSUCCESSFUL;

	*pModuleBaseAddress =
		(uintptr_t)entry.DllBase;

	return status;
}

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_GetModuleBaseAddressFromPebBaseAddress(
	_In_ const HANDLE processHandle,
	_In_ const uintptr_t* const pPebBaseAddress,
	_Out_ uintptr_t* const pModuleBaseAddress)
{
	if (!DAL_IsValidHandle(processHandle))
		return STATUS_INVALID_PARAMETER_1;
	if (pPebBaseAddress == NULL)
		return STATUS_INVALID_PARAMETER_2;
	if (pModuleBaseAddress == NULL)
		return STATUS_INVALID_PARAMETER_3;

	*pModuleBaseAddress = 0ull;

	if (!DAL_IsValidAddress(*pPebBaseAddress))
		return STATUS_INVALID_ADDRESS;

	PEB peb = { 0 };
	NTSTATUS status = DAL_Nt_ReadVirtualMemory(
		processHandle,
		*pPebBaseAddress,
		&peb,
		sizeof(peb));

	if (!NT_SUCCESS(status))
		return status;
	if (!peb.Ldr)
		return STATUS_UNSUCCESSFUL;

	uintptr_t loaderAddress =
		(uintptr_t)peb.Ldr;

	if (!DAL_IsValidAddress(loaderAddress))
		return STATUS_INVALID_ADDRESS;

	PEB_LDR_DATA loaderData = { 0 };
	status = DAL_Nt_ReadVirtualMemory(
		processHandle,
		loaderAddress,
		&loaderData,
		sizeof(loaderData));

	if (!NT_SUCCESS(status))
		return status;

	uintptr_t firstLink =
		(uintptr_t)loaderData.InLoadOrderModuleList.Flink;

	if (!DAL_IsValidAddress(firstLink))
		return STATUS_INVALID_ADDRESS;

	uintptr_t entryAddress =
		firstLink - offsetof(LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

	LDR_DATA_TABLE_ENTRY entry = { 0 };
	status = DAL_Nt_ReadVirtualMemory(
		processHandle,
		entryAddress,
		&entry,
		sizeof(entry));

	if (!NT_SUCCESS(status))
		return status;
	if (entry.DllBase == NULL)
		return STATUS_UNSUCCESSFUL;

	*pModuleBaseAddress =
		(uintptr_t)entry.DllBase;

	return status;
}

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_GetModuleBaseAddressFromPeb(
	_In_ const HANDLE processHandle,
	_In_ const PEB* const pPeb,
	_Out_ uintptr_t* const pModuleBaseAddress)
{
	if (!DAL_IsValidHandle(processHandle))
		return STATUS_INVALID_PARAMETER_1;
	if (pPeb == NULL)
		return STATUS_INVALID_PARAMETER_2;
	if (pModuleBaseAddress == NULL)
		return STATUS_INVALID_PARAMETER_3;

	*pModuleBaseAddress = 0ull;

	if (!pPeb->Ldr)
		return STATUS_UNSUCCESSFUL;

	uintptr_t loaderAddress =
		(uintptr_t)pPeb->Ldr;

	if (!DAL_IsValidAddress(loaderAddress))
		return STATUS_INVALID_ADDRESS;

	PEB_LDR_DATA loaderData = { 0 };
	NTSTATUS status = DAL_Nt_ReadVirtualMemory(
		processHandle,
		loaderAddress,
		&loaderData,
		sizeof(loaderData));

	if (!NT_SUCCESS(status))
		return status;

	uintptr_t firstLink =
		(uintptr_t)loaderData.InLoadOrderModuleList.Flink;

	if (!DAL_IsValidAddress(firstLink))
		return STATUS_INVALID_ADDRESS;

	uintptr_t entryAddress =
		firstLink - offsetof(LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

	LDR_DATA_TABLE_ENTRY entry = { 0 };
	status = DAL_Nt_ReadVirtualMemory(
		processHandle,
		entryAddress,
		&entry,
		sizeof(entry));

	if (!NT_SUCCESS(status))
		return status;
	if (entry.DllBase == NULL)
		return STATUS_UNSUCCESSFUL;

	*pModuleBaseAddress =
		(uintptr_t)entry.DllBase;

	return status;
}

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_GetWindowVisibility(
	_In_ const DWORD processId,
	_Out_ BOOL* const pIsWindowVisible)
{
	if (!DAL_IsValidProcessId(processId))
		return STATUS_INVALID_PARAMETER_1;
	if (pIsWindowVisible == NULL)
		return STATUS_INVALID_PARAMETER_2;

	*pIsWindowVisible = FALSE;

	for (HWND hwnd = GetTopWindow(NULL); hwnd; hwnd = GetNextWindow(hwnd, GW_HWNDNEXT))
	{
		DWORD windowThreadProcessId = 0ul;
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
DAL_Win32_GetProcessArchitecture(
	_In_ const HANDLE processHandle,
	_Out_ USHORT* const pProcessMachine,
	_Out_ USHORT* const pNativeMachine,
	_Out_ BOOL* const pIsWow64)
{
	if (!DAL_IsValidHandle(processHandle))
		return STATUS_INVALID_PARAMETER_1;
	if (pProcessMachine == NULL)
		return STATUS_INVALID_PARAMETER_2;
	if (pNativeMachine == NULL)
		return STATUS_INVALID_PARAMETER_3;
	if (pIsWow64 == NULL)
		return STATUS_INVALID_PARAMETER_4;

	*pProcessMachine = IMAGE_FILE_MACHINE_UNKNOWN;
	*pNativeMachine = IMAGE_FILE_MACHINE_UNKNOWN;
	*pIsWow64 = FALSE;

	NTSTATUS status = IsWow64Process2(
		processHandle,
		// IMAGE_FILE_MACHINE_UNKNOWN if not a WOW64 process
		pProcessMachine,
		// Native architecture of host system
		pNativeMachine) ?
		STATUS_SUCCESS :
		STATUS_UNSUCCESSFUL;

	if (!NT_SUCCESS(status))
		return status;

	*pIsWow64 =
		*pProcessMachine != IMAGE_FILE_MACHINE_UNKNOWN;

	// If running under WOW64, processMachine already contains the guest architecture.
	// Otherwise processMachine is IMAGE_FILE_MACHINE_UNKNOWN, so use the native machine.
	*pProcessMachine = *pIsWow64 ?
		*pProcessMachine :
		*pNativeMachine;

	return STATUS_SUCCESS;
}

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_GetWow64Info(
	_In_ const HANDLE processHandle,
	_Out_ ULONG_PTR* const pWow64Info)
{
	if (!DAL_IsValidHandle(processHandle))
		return STATUS_INVALID_PARAMETER_1;
	if (pWow64Info == NULL)
		return STATUS_INVALID_PARAMETER_2;

	*pWow64Info = 0ull;

	NTSTATUS status = NtQueryInformationProcess(
		processHandle,
		ProcessWow64Information,
		pWow64Info,
		sizeof(ULONG_PTR),
		NULL);

	return status;
}

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_GetProcessModules(
	_In_ const HANDLE processHandle,
	_In_ const DWORD processId,
	_Out_writes_(bufferLength)
	MODULEENTRY32W* const pBuffer,
	_In_ const DWORD bufferLength,
	_Out_ DWORD* const pCopiedLength)
{
	if (!DAL_IsValidHandle(processHandle))
		return STATUS_INVALID_PARAMETER_1;
	if (!DAL_IsValidProcessId(processId))
		return STATUS_INVALID_PARAMETER_2;
	if (pBuffer == NULL)
		return STATUS_INVALID_PARAMETER_3;
	if (bufferLength == 0ul)
		return STATUS_BUFFER_TOO_SMALL;
	if (pCopiedLength == NULL)
		return STATUS_INVALID_PARAMETER_5;

	memset(pBuffer, 0, bufferLength * sizeof(MODULEENTRY32W));
	for (DWORD i = 0ul; i < bufferLength; ++i)
		pBuffer[i].dwSize = sizeof(MODULEENTRY32W);

	*pCopiedLength = 0ul;

	HANDLE snapshotHandle = CreateToolhelp32Snapshot(
		TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
		processId);

	if (!DAL_IsValidHandle(snapshotHandle))
		return STATUS_INVALID_HANDLE;

	MODULEENTRY32W moduleEntry = { 0 };
	moduleEntry.dwSize = sizeof(MODULEENTRY32W);

	NTSTATUS status = Module32FirstW(
		snapshotHandle,
		&moduleEntry) ?
		STATUS_SUCCESS :
		STATUS_UNSUCCESSFUL;

	if (!NT_SUCCESS(status))
	{
		DAL_CloseHandle32(snapshotHandle);
		return status;
	}

	DWORD count = 0ul;
	do
	{
		if (count >= bufferLength)
		{
			DAL_CloseHandle32(snapshotHandle);
			*pCopiedLength = count;
			return STATUS_BUFFER_TOO_SMALL;
		}

		pBuffer[count++] = moduleEntry;

	} while (Module32NextW(snapshotHandle, &moduleEntry));

	DAL_CloseHandle32(snapshotHandle);
	*pCopiedLength = count;
	return STATUS_SUCCESS;
}

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_GetProcessModules(
	_In_ const HANDLE processHandle,
	_In_ const PEB* const pPeb,
	_Out_writes_(bufferLength)
	LDR_DATA_TABLE_ENTRY* const pBuffer,
	_In_ const DWORD bufferLength,
	_Out_ DWORD* const pCopiedLength)
{
	if (!DAL_IsValidHandle(processHandle))
		return STATUS_INVALID_PARAMETER_1;
	if (pPeb == NULL)
		return STATUS_INVALID_PARAMETER_2;
	if (pBuffer == NULL)
		return STATUS_INVALID_PARAMETER_3;
	if (pCopiedLength == NULL)
		return STATUS_INVALID_PARAMETER_5;

	PEB peb = { 0 };

	NTSTATUS status = DAL_Nt_ReadVirtualMemory(
		processHandle,
		(uintptr_t)pPeb,
		&peb,
		sizeof(peb));
	if (!NT_SUCCESS(status))
		return status;

	memset(
		pBuffer,
		0,
		bufferLength * sizeof(LDR_DATA_TABLE_ENTRY));

	*pCopiedLength = 0ul;

	uintptr_t loaderAddress =
		(uintptr_t)peb.Ldr;
	if (!DAL_IsValidAddress(loaderAddress))
		return STATUS_INVALID_ADDRESS;

	PEB_LDR_DATA loaderData = { 0 };
	status = DAL_Nt_ReadVirtualMemory(
		processHandle,
		loaderAddress,
		&loaderData,
		sizeof(loaderData));

	if (!NT_SUCCESS(status))
		return status;
	if (!loaderData.InLoadOrderModuleList.Flink)
		return STATUS_UNSUCCESSFUL;

	uintptr_t listHead =
		loaderAddress + offsetof(PEB_LDR_DATA, InLoadOrderModuleList);

	if (!DAL_IsValidAddress(listHead))
		return STATUS_INVALID_ADDRESS;

	uintptr_t currentLink =
		(uintptr_t)loaderData.InLoadOrderModuleList.Flink;

	if (!DAL_IsValidAddress(currentLink))
		return STATUS_INVALID_ADDRESS;

	DWORD copied = 0ul;
	DWORD sanityCounter = 0ul;
	while (currentLink && currentLink != listHead)
	{
		if (++sanityCounter > MAX_MODULES)
			break;

		if (copied >= bufferLength)
			return STATUS_BUFFER_TOO_SMALL;

		// first remote module = fLink - ILOL offset
		uintptr_t entryAddress =
			currentLink - offsetof(LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

		LDR_DATA_TABLE_ENTRY entry = { 0 };
		status = DAL_Nt_ReadVirtualMemory(
			processHandle,
			entryAddress,
			&entry,
			sizeof(entry));

		if (!NT_SUCCESS(status))
			break;

		pBuffer[copied++] = entry;

		uintptr_t next =
			(uintptr_t)entry.InLoadOrderLinks.Flink;

		if (!DAL_IsValidAddress(next) || next == currentLink)
			break;

		currentLink = next;
	};

	*pCopiedLength = copied;
	return STATUS_SUCCESS;
};

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_GetProcessThreads(
	_In_ const HANDLE processHandle,
	_In_ const DWORD processId,
	_Out_writes_(bufferLength)
	THREADENTRY32* const pBuffer,
	_In_ const DWORD bufferLength,
	_Out_ DWORD* const pCopiedLength)
{
	if (!DAL_IsValidHandle(processHandle))
		return STATUS_INVALID_PARAMETER_1;
	if (!DAL_IsValidProcessId(processId))
		return STATUS_INVALID_PARAMETER_2;
	if (pBuffer == NULL)
		return STATUS_INVALID_PARAMETER_3;
	if (bufferLength == 0ul)
		return STATUS_BUFFER_TOO_SMALL;
	if (pCopiedLength == NULL)
		return STATUS_INVALID_PARAMETER_5;

	memset(pBuffer, 0, bufferLength * sizeof(THREADENTRY32));
	for (DWORD i = 0ul; i < bufferLength; ++i)
		pBuffer[i].dwSize = sizeof(THREADENTRY32);

	*pCopiedLength = 0ul;

	// The processId parameter is technically ignored for TH32CS_SNAPTHREAD.
	HANDLE snapshotHandle = CreateToolhelp32Snapshot(
		TH32CS_SNAPTHREAD,
		processId);

	if (!DAL_IsValidHandle(snapshotHandle))
		return STATUS_INVALID_HANDLE;

	THREADENTRY32 threadEntry = { 0 };
	threadEntry.dwSize = sizeof(THREADENTRY32);
	NTSTATUS status = Thread32First(
		snapshotHandle,
		&threadEntry) ?
		STATUS_SUCCESS :
		STATUS_UNSUCCESSFUL;

	if (!NT_SUCCESS(status))
	{
		DAL_CloseHandle32(snapshotHandle);
		return status;
	}

	DWORD count = 0ul;
	do
	{
		if (threadEntry.th32OwnerProcessID == processId)
		{
			if (count >= bufferLength)
			{
				DAL_CloseHandle32(snapshotHandle);
				*pCopiedLength = count;
				return STATUS_BUFFER_TOO_SMALL;
			}
		}

		pBuffer[count++] = threadEntry;

	} while (Thread32Next(snapshotHandle, &threadEntry));

	DAL_CloseHandle32(snapshotHandle);
	*pCopiedLength = count;
	return STATUS_SUCCESS;
}

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_GetProcessThreads(
	_In_ const HANDLE processHandle,
	_In_ const DWORD processId,
	_Out_writes_(bufferLength)
	SYSTEM_THREAD_INFORMATION* const pBuffer,
	_In_ const DWORD bufferLength,
	_Out_ DWORD* const pCopiedLength)
{
	if (!DAL_IsValidHandle(processHandle))
		return STATUS_INVALID_PARAMETER_1;
	if (!DAL_IsValidProcessId(processId))
		return STATUS_INVALID_PARAMETER_2;
	if (pBuffer == NULL)
		return STATUS_INVALID_PARAMETER_3;
	if (pCopiedLength == NULL)
		return STATUS_INVALID_PARAMETER_5;

	memset(
		pBuffer,
		0,
		bufferLength * sizeof(SYSTEM_THREAD_INFORMATION));

	*pCopiedLength = 0ul;

	DWORD requiredBufferSize = 0ul;
	NTSTATUS status = DAL_Nt_GetQSIBufferSize(
		SystemProcessInformation,
		&requiredBufferSize);

	if (!NT_SUCCESS(status))
		return status;

	BYTE* processInfoBuffer =
		(BYTE*)malloc(requiredBufferSize);
	if (processInfoBuffer == NULL)
		return STATUS_NO_MEMORY;

	status = NtQuerySystemInformation(
		SystemProcessInformation,
		processInfoBuffer,
		requiredBufferSize,
		NULL);

	if (!NT_SUCCESS(status))
	{
		free(processInfoBuffer);
		return status;
	}

	PSYSTEM_PROCESS_INFORMATION processInfo =
		(PSYSTEM_PROCESS_INFORMATION)processInfoBuffer;

	DWORD threadCount = 0ul;
	if (!processInfo)
	{
		free(processInfoBuffer);
		return STATUS_UNSUCCESSFUL;
	}

	while (processInfo)
	{
		DWORD processInfoId =
			(DWORD)(uintptr_t)(processInfo->UniqueProcessId);

		if (processInfoId == processId)
		{
			threadCount = processInfo->NumberOfThreads;
			if (pCopiedLength)
				*pCopiedLength = threadCount;

			if (pBuffer)
			{
				uint32_t toCopy =
					DAL_MinU32(bufferLength, threadCount);

				for (uint32_t i = 0u; i < toCopy; ++i)
					pBuffer[i] = processInfo->Threads[i];
			}
			break;
		}
		if (processInfo->NextEntryOffset == 0)
			break;

		processInfo =
			(PSYSTEM_PROCESS_INFORMATION)
			((BYTE*)processInfo +
				processInfo->NextEntryOffset);
	}

	free(processInfoBuffer);
	return STATUS_SUCCESS;
}

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_GetProcessHandles(
	_In_ const HANDLE processHandle,
	_In_ const DWORD processId,
	_Out_writes_(bufferLength)
	PSS_HANDLE_ENTRY* const pBuffer,
	_In_ const DWORD bufferLength,
	_Out_ DWORD* const pCopiedLength)
{
	if (!DAL_IsValidHandle(processHandle))
		return STATUS_INVALID_PARAMETER_1;
	if (!DAL_IsValidProcessId(processId))
		return STATUS_INVALID_PARAMETER_2;
	if (pBuffer == NULL)
		return STATUS_INVALID_PARAMETER_3;
	if (bufferLength == 0ul)
		return STATUS_BUFFER_TOO_SMALL;
	if (pCopiedLength == NULL)
		return STATUS_INVALID_PARAMETER_5;

	memset(pBuffer, 0, bufferLength * sizeof(PSS_HANDLE_ENTRY));
	*pCopiedLength = 0ul;

	HPSS pssSnapshotHandle = { 0 };
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

	HPSSWALK walkMarkerHandle = { 0 };
	if (PssWalkMarkerCreate(NULL, &walkMarkerHandle)
		!= ERROR_SUCCESS)
	{
		PssFreeSnapshot(GetCurrentProcess(), pssSnapshotHandle);
		return STATUS_UNSUCCESSFUL;
	}

	DWORD count = 0ul;
	while (true)
	{
		PSS_HANDLE_ENTRY handleEntry = { 0 };
		DWORD walkStatus = PssWalkSnapshot(
			pssSnapshotHandle,
			PSS_WALK_HANDLES,
			walkMarkerHandle,
			&handleEntry,
			sizeof(handleEntry));

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

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_GetProcessHandles(
	_In_ const HANDLE processHandle,
	_In_ const DWORD processId,
	_Out_writes_(bufferLength)
	SYSTEM_HANDLE_TABLE_ENTRY_INFO* const pBuffer,
	_In_ const DWORD bufferLength,
	_Out_ DWORD* const pCopiedLength)
{
	if (!DAL_IsValidHandle(processHandle))
		return STATUS_INVALID_PARAMETER_1;
	if (!DAL_IsValidProcessId(processId))
		return STATUS_INVALID_PARAMETER_2;
	if (pBuffer == NULL)
		return STATUS_INVALID_PARAMETER_3;
	if (pCopiedLength == NULL)
		return STATUS_INVALID_PARAMETER_5;

	memset(
		pBuffer,
		0,
		bufferLength *
		sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO));

	*pCopiedLength = 0ul;

	DWORD requiredBufferSize = 0ul;
	NTSTATUS status = DAL_Nt_GetQSIBufferSize(
		SystemHandleInformation,
		&requiredBufferSize);
	requiredBufferSize += PAGE_SIZE;

	if (!NT_SUCCESS(status))
		return status;

	if (!requiredBufferSize)
		return STATUS_UNSUCCESSFUL;

	BYTE* handleInfoBuffer =
		(BYTE*)malloc(requiredBufferSize);
	if (handleInfoBuffer == NULL)
		return STATUS_NO_MEMORY;

	status = NtQuerySystemInformation(
		SystemHandleInformation,
		handleInfoBuffer,
		requiredBufferSize,
		NULL);

	if (!NT_SUCCESS(status))
	{
		free(handleInfoBuffer);
		return status;
	}

	PSYSTEM_HANDLE_INFORMATION handleInfo =
		(PSYSTEM_HANDLE_INFORMATION)handleInfoBuffer;

	if (!handleInfo)
	{
		free(handleInfoBuffer);
		return STATUS_UNSUCCESSFUL;
	}

	DWORD copied = 0ul;
	DWORD total = 0ul;

	for (DWORD i = 0ul; i < handleInfo->NumberOfHandles; ++i)
	{
		const SYSTEM_HANDLE_TABLE_ENTRY_INFO* entry =
			&handleInfo->Handles[i];

		if ((DWORD)entry->UniqueProcessId != processId)
			continue;

		if (copied < bufferLength)
		{
			pBuffer[copied] = *entry;
			++copied;
		}

		++total;
	}

	free(handleInfoBuffer);
	return STATUS_SUCCESS;
}