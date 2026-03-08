#define NOMINMAX
#include "WindowsProviderNt.h"
#include "MemoryService.h"
#include <algorithm>
// #pragma comment(lib, "ntdll.lib")

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

#ifndef NT_CURRENT_PROCESS
#define NT_CURRENT_PROCESS ((HANDLE)(LONG_PTR)-1)
#endif // !NT_CURRENT_PROCESS

namespace Muninn::Data
{
#pragma region WRITE
	MUNINN_API NTSTATUS MUNINN_CALL
		OpenProcessHandleNt(
			_In_ const DWORD processId,
			_In_ const ACCESS_MASK accessMask,
			_Out_ HANDLE* const pHandle) noexcept
	{
		if (!IsValidProcessId(processId))
			return STATUS_INVALID_PARAMETER_1;
		if (pHandle == nullptr)
			return STATUS_INVALID_PARAMETER_3;

		*pHandle = nullptr;

		OBJECT_ATTRIBUTES objectAttributes{};
		objectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);

		CLIENT_ID clientId{};
		clientId.UniqueProcess
			= reinterpret_cast<HANDLE>(static_cast<uintptr_t>(processId));
		clientId.UniqueThread = nullptr;

		NTSTATUS status{ NtOpenProcess(
			pHandle,
			accessMask,
			&objectAttributes,
			&clientId) };

		if (!IsValidHandle(*pHandle))
			*pHandle = nullptr;

		return status;
	}

	MUNINN_API NTSTATUS MUNINN_CALL
		CloseHandleNt(_In_ const HANDLE handle) noexcept
	{
		if (!IsValidHandle(handle))
			// previously STATUS_INVALID_HANDLE
			return STATUS_INVALID_PARAMETER_1;

		return NtClose(handle);
	}

	MUNINN_API NTSTATUS MUNINN_CALL
		DuplicateHandleNt(
			_In_ const HANDLE sourceHandle,
			_In_ const DWORD processId,
			_Out_ HANDLE* const pDuplicatedHandle) noexcept
	{
		if (!IsValidHandle(sourceHandle))
			return STATUS_INVALID_PARAMETER_1;
		if (!IsValidProcessId(processId))
			return STATUS_INVALID_PARAMETER_2;
		if (pDuplicatedHandle == nullptr)
			return STATUS_INVALID_PARAMETER_3;

		*pDuplicatedHandle = nullptr;

		// Prefer explicity over InitializeObjectAttributes(p, n, a, r, s)
		OBJECT_ATTRIBUTES objectAttributes{};
		objectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
		objectAttributes.ObjectName = nullptr;
		objectAttributes.Attributes = 0ul;
		objectAttributes.RootDirectory = nullptr;
		objectAttributes.SecurityDescriptor = nullptr;
		objectAttributes.SecurityQualityOfService = nullptr;

		CLIENT_ID clientId{};
		clientId.UniqueProcess = reinterpret_cast<HANDLE>(
			static_cast<uintptr_t>(processId));
		clientId.UniqueThread = nullptr;

		HANDLE remoteProcessHandle{};
		NTSTATUS status = NtOpenProcess(
			&remoteProcessHandle,
			PROCESS_DUP_HANDLE,
			&objectAttributes,
			&clientId);
		if (!NT_SUCCESS(status)) return status;

		HANDLE duplicatedHandle{};
		status = NtDuplicateObject(
			remoteProcessHandle,
			sourceHandle,
			NT_CURRENT_PROCESS,
			pDuplicatedHandle,
			0ul,
			0ul,
			DUPLICATE_SAME_ACCESS);
		CloseHandleNt(remoteProcessHandle);

		if (!NT_SUCCESS(status))
			*pDuplicatedHandle = nullptr;

		return status;
	}

	MUNINN_API NTSTATUS MUNINN_CALL
		OpenProcessTokenHandleNt(
			_In_ const HANDLE processHandle,
			_In_ const ACCESS_MASK accessMask,
			_Out_ HANDLE* const pTokenHandle) noexcept
	{
		if (!IsValidHandle(processHandle))
			return STATUS_INVALID_PARAMETER_1;
		if (pTokenHandle == nullptr)
			return STATUS_INVALID_PARAMETER_3;

		*pTokenHandle = nullptr;

		NTSTATUS status{ NtOpenProcessToken(
			processHandle,
			accessMask,
			pTokenHandle) };

		if (!NT_SUCCESS(status))
			*pTokenHandle = nullptr;

		return status;
	}
#pragma endregion

#pragma region READ
	MUNINN_API NTSTATUS MUNINN_CALL
		GetFullLuidNt(
			_In_ const LUID luid,
			_Out_ uint64_t* const pFullLuid) noexcept
	{
		if (pFullLuid == nullptr)
			return STATUS_INVALID_PARAMETER_2;

		*pFullLuid
			= (uint64_t(luid.HighPart) << 32l) |
			uint64_t(luid.LowPart);

		return STATUS_SUCCESS;
	}

	MUNINN_API NTSTATUS MUNINN_CALL
		GetQSIBufferSizeNt(
			_In_ const SYSTEM_INFORMATION_CLASS infoClass,
			_Out_ DWORD* const pRequiredBufferSize) noexcept
	{
		if (pRequiredBufferSize == nullptr)
			return STATUS_INVALID_PARAMETER_2;

		*pRequiredBufferSize = 0ul;

		BYTE buffer[QSI_MIN_BUFFER_SIZE];
		NTSTATUS status{ NtQuerySystemInformation(
			infoClass,
			buffer,
			sizeof(buffer),
			pRequiredBufferSize) };

		if (status != STATUS_INFO_LENGTH_MISMATCH)
			*pRequiredBufferSize = 0ul;

		return status;
	}

	MUNINN_API NTSTATUS MUNINN_CALL
		GetQOBufferSizeNt(
			_In_ const HANDLE duplicatedHandle,
			_In_ const OBJECT_INFORMATION_CLASS infoClass,
			_Out_ DWORD* const pRequiredBufferSize) noexcept
	{
		if (!IsValidHandle(duplicatedHandle))
			return STATUS_INVALID_PARAMETER_1;
		if (pRequiredBufferSize == nullptr)
			return STATUS_INVALID_PARAMETER_3;

		*pRequiredBufferSize = 0ul;

		NTSTATUS status{ NtQueryObject(
			duplicatedHandle,
			infoClass,
			nullptr,
			0ul,
			pRequiredBufferSize) };

		if (status != STATUS_INFO_LENGTH_MISMATCH)
			*pRequiredBufferSize = 0ul;

		return status;
	}

	MUNINN_API NTSTATUS MUNINN_CALL
		GetQITBufferSizeNt(
			_In_ const HANDLE tokenHandle,
			_In_ const _TOKEN_INFORMATION_CLASS infoClass,
			_Out_ DWORD* const pRequiredBufferSize) noexcept
	{
		if (!IsValidHandle(tokenHandle))
			return STATUS_INVALID_PARAMETER_1;
		if (pRequiredBufferSize == nullptr)
			return STATUS_INVALID_PARAMETER_3;

		*pRequiredBufferSize = 0ul;

		NTSTATUS status{ NtQueryInformationToken(
			tokenHandle,
			infoClass,
			nullptr,
			0,
			pRequiredBufferSize) };

		if (status != STATUS_INFO_LENGTH_MISMATCH)
			*pRequiredBufferSize = 0ul;

		return status;
	}

	MUNINN_API NTSTATUS MUNINN_CALL
		GetObjectNameNt(
			_In_ const HANDLE sourceHandle,
			_In_ const DWORD processId,
			_Out_writes_(bufferLength)
			WCHAR* const pBuffer,
			_In_ const DWORD bufferLength,
			_Out_ DWORD* const pCopiedLength) noexcept
	{
		if (!IsValidHandle(sourceHandle))
			return STATUS_INVALID_PARAMETER_1;
		if (!IsValidProcessId(processId))
			return STATUS_INVALID_PARAMETER_2;
		if (pBuffer == nullptr)
			return STATUS_INVALID_PARAMETER_3;
		if (bufferLength == 0ul)
			return STATUS_BUFFER_TOO_SMALL;
		if (pCopiedLength == nullptr)
			return STATUS_INVALID_PARAMETER_5;

		*pBuffer = L'\0';
		*pCopiedLength = 0ul;

		HANDLE duplicatedHandle{};
		NTSTATUS status{ DuplicateHandleNt(
			sourceHandle,
			processId,
			&duplicatedHandle) };

		if (!NT_SUCCESS(status))
			return status;

		if (!IsValidHandle(duplicatedHandle))
			return STATUS_INVALID_HANDLE;

		DWORD requiredSize{};
		status = GetQOBufferSizeNt(
			duplicatedHandle,
			ObjectNameInformation,
			&requiredSize);

		if (status != STATUS_INFO_LENGTH_MISMATCH &&
			!NT_SUCCESS(status))
		{
			CloseHandleNt(duplicatedHandle);
			return status;
		}

		if (!requiredSize)
		{
			CloseHandleNt(duplicatedHandle);
			return STATUS_UNSUCCESSFUL;
		}

		BYTE* nameInfoBuffer{ new BYTE[requiredSize] };
		status = NtQueryObject(
			duplicatedHandle,
			ObjectNameInformation,
			nameInfoBuffer,
			requiredSize,
			nullptr);

		if (!NT_SUCCESS(status))
		{
			delete[] nameInfoBuffer;
			CloseHandleNt(duplicatedHandle);
			return status;
		}

		OBJECT_NAME_INFORMATION* nameInfo{
			reinterpret_cast<OBJECT_NAME_INFORMATION*>(nameInfoBuffer) };

		if (nameInfo->Name.Buffer &&
			nameInfo->Name.Length > 0)
		{
			DWORD charsToCopy{
				nameInfo->Name.Length / sizeof(WCHAR) };

			// leave room for null terminator -> (-1ul)
			if (charsToCopy >= bufferLength)
				charsToCopy = bufferLength - 1ul;

			for (DWORD i{}; i < charsToCopy; ++i)
				pBuffer[i] = nameInfo->Name.Buffer[i];

			pBuffer[charsToCopy] = L'\0';
			*pCopiedLength = charsToCopy;
		}

		delete[] nameInfoBuffer;
		CloseHandleNt(duplicatedHandle);
		return STATUS_SUCCESS;
	}

	// Rework from here on down
	MUNINN_API NTSTATUS MUNINN_CALL
		GetObjectTypeNameNt(
			_In_ const HANDLE sourceHandle,
			_In_ const DWORD processId,
			_Out_writes_(bufferLength)
			WCHAR* const pBuffer,
			_In_ const DWORD bufferLength,
			_Out_ DWORD* const pCopiedLength) noexcept
	{
		if (!IsValidHandle(sourceHandle))
			return STATUS_INVALID_PARAMETER_1;
		if (!IsValidProcessId(processId))
			return STATUS_INVALID_PARAMETER_2;
		if (pBuffer == nullptr)
			return STATUS_INVALID_PARAMETER_3;
		if (bufferLength == 0ul)
			return STATUS_BUFFER_TOO_SMALL;
		if (pCopiedLength == nullptr)
			return STATUS_INVALID_PARAMETER_5;

		*pBuffer = L'\0';
		*pCopiedLength = 0ul;

		HANDLE duplicatedHandle{};
		NTSTATUS status{ DuplicateHandleNt(
			sourceHandle,
			processId,
			&duplicatedHandle) };

		if (!NT_SUCCESS(status))
			return status;

		if (!IsValidHandle(duplicatedHandle))
			return STATUS_INVALID_HANDLE;

		DWORD requiredSize{};
		status = GetQOBufferSizeNt(
			duplicatedHandle,
			ObjectTypeInformation,
			&requiredSize);

		if (status != STATUS_INFO_LENGTH_MISMATCH &&
			!NT_SUCCESS(status))
		{
			CloseHandleNt(duplicatedHandle);
			return status;
		}

		if (!requiredSize)
		{
			CloseHandleNt(duplicatedHandle);
			return STATUS_UNSUCCESSFUL;
		}

		BYTE* typeInfoBuffer{ new BYTE[requiredSize] };
		status = NtQueryObject(
			duplicatedHandle,
			ObjectTypeInformation,
			typeInfoBuffer,
			requiredSize,
			nullptr);

		if (!NT_SUCCESS(status))
		{
			delete[] typeInfoBuffer;
			CloseHandleNt(duplicatedHandle);
			return status;
		}

		OBJECT_TYPE_INFORMATION* typeInfo{
			reinterpret_cast<OBJECT_TYPE_INFORMATION*>(typeInfoBuffer) };

		if (typeInfo->TypeName.Buffer &&
			typeInfo->TypeName.Length > 0)
		{
			DWORD charsToCopy{
				typeInfo->TypeName.Length / sizeof(WCHAR) };

			// leave room for null terminator -> (-1ul)
			if (charsToCopy >= bufferLength)
				charsToCopy = bufferLength - 1ul;

			for (DWORD i{}; i < charsToCopy; ++i)
				pBuffer[i] = typeInfo->TypeName.Buffer[i];

			pBuffer[charsToCopy] = L'\0';
			*pCopiedLength = charsToCopy;
		}

		delete[] typeInfoBuffer;
		CloseHandleNt(duplicatedHandle);
		return STATUS_SUCCESS;
	}

	MUNINN_API NTSTATUS MUNINN_CALL
		GetRemoteUnicodeStringNt(
			_In_ const HANDLE processHandle,
			_In_ const UNICODE_STRING* const pRemoteUnicodeString,
			_Out_writes_(bufferLength)
			WCHAR* const pBuffer,
			_In_ const DWORD bufferLength,
			_Out_ DWORD* const pCopiedLength) noexcept
	{
		if (!IsValidHandle(processHandle))
			return STATUS_INVALID_PARAMETER_1;
		if (pRemoteUnicodeString == nullptr)
			return STATUS_INVALID_PARAMETER_2;
		if (pBuffer == nullptr)
			return STATUS_INVALID_PARAMETER_3;
		if (bufferLength == 0ul)
			return STATUS_BUFFER_TOO_SMALL;
		if (pCopiedLength == nullptr)
			return STATUS_INVALID_PARAMETER_5;

		*pBuffer = L'\0';
		*pCopiedLength = 0ul;

		// The string is empty
		if (pRemoteUnicodeString->Buffer == nullptr ||
			pRemoteUnicodeString->Length == 0)
			return STATUS_SUCCESS;

		DWORD charsToCopy{
			pRemoteUnicodeString->Length / sizeof(WCHAR) };

		if (charsToCopy >= bufferLength)
			charsToCopy = bufferLength - 1ul;

		SIZE_T bytesToRead{
			charsToCopy * sizeof(WCHAR) };

		NTSTATUS status{ NtReadVirtualMemory(
			processHandle,
			pRemoteUnicodeString->Buffer,
			pBuffer,
			bytesToRead,
			nullptr) };

		if (!NT_SUCCESS(status))
			return status;

		pBuffer[charsToCopy] = L'\0';
		*pCopiedLength = charsToCopy;

		return status;
	}

	MUNINN_API NTSTATUS MUNINN_CALL
		GetSystemProcessInformationNt(
			_In_ const HANDLE processHandle,
			_Out_ SYSTEM_PROCESS_INFORMATION* const pSystemProcessInfo) noexcept
	{
		if (!IsValidHandle(processHandle))
			return STATUS_INVALID_PARAMETER_1;
		if (pSystemProcessInfo == nullptr)
			return STATUS_INVALID_PARAMETER_2;

		*pSystemProcessInfo = {};

		DWORD requiredBufferSize{};
		NTSTATUS status{ GetQSIBufferSizeNt(
		SystemProcessInformation,
			&requiredBufferSize) };

		if (!requiredBufferSize)
			return STATUS_UNSUCCESSFUL;

		BYTE* systemInfoBuffer{
			new BYTE[requiredBufferSize] };

		status = NtQuerySystemInformation(
			SystemProcessInformation,
			systemInfoBuffer,
			requiredBufferSize,
			nullptr);

		if (!NT_SUCCESS(status))
			delete[] systemInfoBuffer;

		return status;
	}

	MUNINN_API NTSTATUS MUNINN_CALL
		GetProcessInformationNt(
			_In_ const HANDLE processHandle,
			_Out_ PROCESS_EXTENDED_BASIC_INFORMATION* const pProcessInfo) noexcept
	{
		if (!IsValidHandle(processHandle))
			return STATUS_INVALID_PARAMETER_1;
		if (pProcessInfo == nullptr)
			return STATUS_INVALID_PARAMETER_2;

		*pProcessInfo = {};

		NTSTATUS status{ NtQueryInformationProcess(
			processHandle,
			ProcessBasicInformation,
			pProcessInfo,
			sizeof(PROCESS_EXTENDED_BASIC_INFORMATION),
			nullptr) };

		if (!NT_SUCCESS(status))
			*pProcessInfo = {};

		return status;
	}

	MUNINN_API NTSTATUS MUNINN_CALL
		GetImageFileNameNt(
			_In_ const HANDLE processHandle,
			_Out_writes_(bufferLength)
			WCHAR* const pBuffer,
			_In_ const DWORD bufferLength,
			_Out_ DWORD* const pCopiedLength) noexcept
	{
		if (!IsValidHandle(processHandle))
			return STATUS_INVALID_PARAMETER_1;
		if (pBuffer == nullptr)
			return STATUS_INVALID_PARAMETER_2;
		if (bufferLength == 0ul)
			return STATUS_BUFFER_TOO_SMALL;
		if (pCopiedLength == nullptr)
			return STATUS_INVALID_PARAMETER_4;

		*pBuffer = L'\0';
		*pCopiedLength = 0ul;

		BYTE imageFileNameBuffer[MAX_PATH]{};
		NTSTATUS status{ NtQueryInformationProcess(
			processHandle,
			ProcessImageFileName,
			imageFileNameBuffer,
			sizeof(imageFileNameBuffer),
			nullptr) };

		if (!NT_SUCCESS(status))
			return status;

		PUNICODE_STRING pImageFileName{
			reinterpret_cast<PUNICODE_STRING>(imageFileNameBuffer) };

		if (pImageFileName->Buffer &&
			pImageFileName->Length)
		{
			DWORD charsToCopy{
				pImageFileName->Length / sizeof(WCHAR) };

			if (charsToCopy >= bufferLength)
				charsToCopy = bufferLength - 1ul;

			for (DWORD i{}; i < charsToCopy; ++i)
				pBuffer[i] = pImageFileName->Buffer[i];

			pBuffer[charsToCopy] = L'\0';
			*pCopiedLength = charsToCopy;
		}

		return status;
	}

	MUNINN_API NTSTATUS MUNINN_CALL
		GetImageFileNameWin32Nt(
			_In_ const HANDLE processHandle,
			_Out_writes_(bufferLength)
			WCHAR* const pBuffer,
			_In_ const DWORD bufferLength,
			_Out_ DWORD* const pCopiedLength) noexcept
	{
		if (!IsValidHandle(processHandle))
			return STATUS_INVALID_PARAMETER_1;
		if (pBuffer == nullptr)
			return STATUS_INVALID_PARAMETER_2;
		if (bufferLength == 0ul)
			return STATUS_BUFFER_TOO_SMALL;
		if (pCopiedLength == nullptr)
			return STATUS_INVALID_PARAMETER_4;

		*pBuffer = L'\0';
		*pCopiedLength = 0ul;

		BYTE imageFileNameBuffer[MAX_PATH]{};
		NTSTATUS status{ NtQueryInformationProcess(
			processHandle,
			ProcessImageFileNameWin32,
			imageFileNameBuffer,
			sizeof(imageFileNameBuffer),
			nullptr) };

		if (!NT_SUCCESS(status))
			return status;

		PUNICODE_STRING pImageFileName{
			reinterpret_cast<PUNICODE_STRING>(imageFileNameBuffer) };

		if (pImageFileName->Buffer &&
			pImageFileName->Length)
		{
			DWORD charsToCopy{
				pImageFileName->Length / sizeof(WCHAR) };

			if (charsToCopy >= bufferLength)
				charsToCopy = bufferLength - 1ul;

			for (DWORD i{}; i < charsToCopy; ++i)
				pBuffer[i] = pImageFileName->Buffer[i];

			pBuffer[charsToCopy] = L'\0';
			*pCopiedLength = charsToCopy;
		}

		return status;
	}

	MUNINN_API NTSTATUS MUNINN_CALL
		GetPebBaseAddressNt(
			_In_ const HANDLE processHandle,
			_Out_ uintptr_t* const pPebBaseAddress) noexcept
	{
		if (!IsValidHandle(processHandle))
			return STATUS_INVALID_PARAMETER_1;
		if (pPebBaseAddress == nullptr)
			return STATUS_INVALID_PARAMETER_2;

		*pPebBaseAddress = 0ull;

		PROCESS_EXTENDED_BASIC_INFORMATION processInfo{};
		NTSTATUS status{ GetProcessInformationNt(
			processHandle,
			&processInfo) };

		if (!NT_SUCCESS(status))
			return status;

		*pPebBaseAddress =
			reinterpret_cast<uintptr_t>(processInfo.BasicInfo.PebBaseAddress);

		if (!IsValidAddress(*pPebBaseAddress))
		{
			*pPebBaseAddress = 0ull;
			return STATUS_UNSUCCESSFUL;
		}

		return STATUS_SUCCESS;
	}

	MUNINN_API NTSTATUS MUNINN_CALL
		GetPebBaseAddressFromProcessInfoNt(
			_In_ const PROCESS_EXTENDED_BASIC_INFORMATION* const pProcessInfo,
			_Out_ uintptr_t* const pPebBaseAddress) noexcept
	{
		if (pProcessInfo == nullptr)
			return STATUS_INVALID_PARAMETER_2;
		if (pPebBaseAddress == nullptr)
			return STATUS_INVALID_PARAMETER_2;

		*pPebBaseAddress =
			reinterpret_cast<uintptr_t>(pProcessInfo->BasicInfo.PebBaseAddress);

		if (!IsValidAddress(*pPebBaseAddress))
		{
			*pPebBaseAddress = 0ull;
			return STATUS_UNSUCCESSFUL;
		}

		return STATUS_SUCCESS;
	}

	MUNINN_API NTSTATUS MUNINN_CALL
		GetPebBaseAddressAndProcessInfoNt(
			_In_ const HANDLE processHandle,
			_Out_ uintptr_t* const pPebBaseAddress,
			_Out_ PROCESS_EXTENDED_BASIC_INFORMATION* const pProcessInfo) noexcept
	{
		if (!IsValidHandle(processHandle))
			return STATUS_INVALID_PARAMETER;
		if (pPebBaseAddress == nullptr ||
			pProcessInfo == nullptr)
			return STATUS_INVALID_PARAMETER;

		*pPebBaseAddress = 0ull;
		*pProcessInfo = {};

		NTSTATUS status{ GetProcessInformationNt(
			processHandle,
			pProcessInfo) };

		if (!NT_SUCCESS(status))
			return status;

		*pPebBaseAddress =
			reinterpret_cast<uintptr_t>(pProcessInfo->BasicInfo.PebBaseAddress);

		if (!IsValidAddress(*pPebBaseAddress))
		{
			*pPebBaseAddress = 0ull;
			*pProcessInfo = {};
			return STATUS_UNSUCCESSFUL;
		}

		return STATUS_SUCCESS;
	}

	MUNINN_API NTSTATUS MUNINN_CALL
		GetPebNt(
			_In_ const HANDLE processHandle,
			_Out_ PEB* const pPeb) noexcept
	{
		if (!IsValidHandle(processHandle))
			return STATUS_INVALID_PARAMETER_1;
		if (pPeb == nullptr)
			return STATUS_INVALID_PARAMETER_2;

		*pPeb = {};

		uintptr_t pebBaseAddress{};
		NTSTATUS status{ GetPebBaseAddressNt(
			processHandle,
			&pebBaseAddress) };

		if (!NT_SUCCESS(status))
			return status;

		if (!IsValidAddress(pebBaseAddress))
			return STATUS_INVALID_ADDRESS;

		status = ReadVirtualMemoryNt<PEB>(
			processHandle,
			pebBaseAddress,
			*pPeb);

		if (!NT_SUCCESS(status))
			*pPeb = {};

		return status;
	}

	MUNINN_API NTSTATUS MUNINN_CALL
		GetPebAndPebBaseAddressNt(
			_In_ const HANDLE processHandle,
			_Out_ uintptr_t* const pPebBaseAddress,
			_Out_ PEB* const pPeb) noexcept
	{
		if (!IsValidHandle(processHandle))
			return STATUS_INVALID_PARAMETER_1;
		if (pPebBaseAddress == nullptr)
			return STATUS_INVALID_PARAMETER_2;
		if (pPeb == nullptr)
			return STATUS_INVALID_PARAMETER_3;

		*pPebBaseAddress = 0ull;
		*pPeb = {};

		NTSTATUS status{ GetPebBaseAddressNt(
			processHandle,
			pPebBaseAddress) };

		if (!NT_SUCCESS(status))
			return status;

		status = ReadVirtualMemoryNt<PEB>(
			processHandle,
			*pPebBaseAddress,
			*pPeb);

		if (!NT_SUCCESS(status))
		{
			*pPeb = {};
			*pPebBaseAddress = 0ull;
		}

		return status;
	}

	MUNINN_API NTSTATUS MUNINN_CALL
		GetModuleBaseAddressNt(
			_In_ const HANDLE processHandle,
			_Out_ uintptr_t* const pModuleBaseAddress) noexcept
	{
		if (!IsValidHandle(processHandle))
			return STATUS_INVALID_PARAMETER_1;
		if (pModuleBaseAddress == nullptr)
			return STATUS_INVALID_PARAMETER_2;

		*pModuleBaseAddress = 0ull;

		uintptr_t pebBaseAddress{};
		PROCESS_EXTENDED_BASIC_INFORMATION processInfo{};
		NTSTATUS status{ GetPebBaseAddressAndProcessInfoNt(
			processHandle,
			&pebBaseAddress,
			&processInfo) };

		if (!NT_SUCCESS(status))
			return status;

		if (!IsValidAddress(pebBaseAddress))
			return STATUS_INVALID_ADDRESS;

		PEB peb{};
		status = ReadVirtualMemoryNt<PEB>(
			processHandle,
			pebBaseAddress,
			peb);

		if (!NT_SUCCESS(status))
			return status;
		if (!peb.Ldr)
			return STATUS_UNSUCCESSFUL;

		uintptr_t loaderAddress{
			reinterpret_cast<uintptr_t>(peb.Ldr) };
		if (!IsValidAddress(loaderAddress))
			return STATUS_INVALID_ADDRESS;

		// Read loader data
		PEB_LDR_DATA loaderData{};
		status = ReadVirtualMemoryNt<PEB_LDR_DATA>(
			processHandle,
			loaderAddress,
			loaderData);

		if (!NT_SUCCESS(status))
			return status;

		// First module in load order list
		uintptr_t firstLink{ reinterpret_cast<uintptr_t>(
			loaderData.InLoadOrderModuleList.Flink) };
		if (!IsValidAddress(firstLink))
			return STATUS_INVALID_ADDRESS;

		// Get the LDR_DATA_TABLE_ENTRY
		uintptr_t entryAddress{
			firstLink - offsetof(LDR_DATA_TABLE_ENTRY, InLoadOrderLinks) };
		LDR_DATA_TABLE_ENTRY entry{};
		status = ReadVirtualMemoryNt(
			processHandle,
			entryAddress,
			entry);

		if (entry.DllBase == nullptr)
			return STATUS_UNSUCCESSFUL;

		*pModuleBaseAddress
			= reinterpret_cast<uintptr_t>(entry.DllBase);

		return status;
	}

	// AI generated, to be reviewed
	MUNINN_API NTSTATUS MUNINN_CALL
		GetModuleBaseAddressFromProcessInfoNt(
			_In_ const HANDLE processHandle,
			_In_ const PROCESS_EXTENDED_BASIC_INFORMATION* const processInfo,
			_Out_ uintptr_t* const pModuleBaseAddress) noexcept
	{
		if (!IsValidHandle(processHandle))
			return STATUS_INVALID_PARAMETER_1;
		if (processInfo == nullptr)
			return STATUS_INVALID_PARAMETER_2;
		if (pModuleBaseAddress == nullptr)
			return STATUS_INVALID_PARAMETER_3;

		*pModuleBaseAddress = 0ull;

		uintptr_t pebBaseAddress{ reinterpret_cast<uintptr_t>(
			processInfo->BasicInfo.PebBaseAddress) };

		if (!IsValidAddress(pebBaseAddress))
			return STATUS_INVALID_ADDRESS;

		PEB peb{};
		NTSTATUS status{ ReadVirtualMemoryNt<PEB>(
			processHandle,
			pebBaseAddress,
			peb) };

		if (!NT_SUCCESS(status))
			return status;
		if (!peb.Ldr)
			return STATUS_UNSUCCESSFUL;

		uintptr_t loaderAddress{
			reinterpret_cast<uintptr_t>(peb.Ldr) };

		if (!IsValidAddress(loaderAddress))
			return STATUS_INVALID_ADDRESS;

		PEB_LDR_DATA loaderData{};
		status = ReadVirtualMemoryNt<PEB_LDR_DATA>(
			processHandle,
			loaderAddress,
			loaderData);

		if (!NT_SUCCESS(status))
			return status;

		uintptr_t firstLink{ reinterpret_cast<uintptr_t>(
				loaderData.InLoadOrderModuleList.Flink) };

		if (!IsValidAddress(firstLink))
			return STATUS_INVALID_ADDRESS;

		uintptr_t entryAddress{
			firstLink - offsetof(LDR_DATA_TABLE_ENTRY, InLoadOrderLinks) };

		LDR_DATA_TABLE_ENTRY entry{};
		status = ReadVirtualMemoryNt(
			processHandle,
			entryAddress,
			entry);

		if (!NT_SUCCESS(status))
			return status;
		if (entry.DllBase == nullptr)
			return STATUS_UNSUCCESSFUL;

		*pModuleBaseAddress =
			reinterpret_cast<uintptr_t>(entry.DllBase);

		return status;
	}

	// AI generated, to be reviewed
	MUNINN_API NTSTATUS MUNINN_CALL
		GetModuleBaseAddressFromPebBaseAddressNt(
			_In_ const HANDLE processHandle,
			_In_ const uintptr_t* const pPebBaseAddress,
			_Out_ uintptr_t* const pModuleBaseAddress) noexcept
	{
		if (!IsValidHandle(processHandle))
			return STATUS_INVALID_PARAMETER_1;
		if (pPebBaseAddress == nullptr)
			return STATUS_INVALID_PARAMETER_2;
		if (pModuleBaseAddress == nullptr)
			return STATUS_INVALID_PARAMETER_3;

		*pModuleBaseAddress = 0ull;

		if (!IsValidAddress(*pPebBaseAddress))
			return STATUS_INVALID_ADDRESS;

		PEB peb{};
		NTSTATUS status{ ReadVirtualMemoryNt<PEB>(
			processHandle,
			*pPebBaseAddress,
			peb) };

		if (!NT_SUCCESS(status))
			return status;
		if (!peb.Ldr)
			return STATUS_UNSUCCESSFUL;

		uintptr_t loaderAddress{
			reinterpret_cast<uintptr_t>(peb.Ldr) };

		if (!IsValidAddress(loaderAddress))
			return STATUS_INVALID_ADDRESS;

		PEB_LDR_DATA loaderData{};
		status = ReadVirtualMemoryNt<PEB_LDR_DATA>(
			processHandle,
			loaderAddress,
			loaderData);

		if (!NT_SUCCESS(status))
			return status;

		uintptr_t firstLink{
			reinterpret_cast<uintptr_t>(
				loaderData.InLoadOrderModuleList.Flink) };

		if (!IsValidAddress(firstLink))
			return STATUS_INVALID_ADDRESS;

		uintptr_t entryAddress{
			firstLink - offsetof(LDR_DATA_TABLE_ENTRY, InLoadOrderLinks) };

		LDR_DATA_TABLE_ENTRY entry{};
		status = ReadVirtualMemoryNt(
			processHandle,
			entryAddress,
			entry);

		if (!NT_SUCCESS(status))
			return status;
		if (entry.DllBase == nullptr)
			return STATUS_UNSUCCESSFUL;

		*pModuleBaseAddress =
			reinterpret_cast<uintptr_t>(entry.DllBase);

		return status;
	}

	MUNINN_API NTSTATUS MUNINN_CALL
		GetModuleBaseAddressFromPebNt(
			_In_ const HANDLE processHandle,
			_In_ const PEB* const pPeb,
			_Out_ uintptr_t* const pModuleBaseAddress) noexcept
	{
		if (!IsValidHandle(processHandle))
			return STATUS_INVALID_PARAMETER_1;
		if (pPeb == nullptr)
			return STATUS_INVALID_PARAMETER_2;
		if (pModuleBaseAddress == nullptr)
			return STATUS_INVALID_PARAMETER_3;

		*pModuleBaseAddress = 0ull;

		if (!pPeb->Ldr)
			return STATUS_UNSUCCESSFUL;

		uintptr_t loaderAddress{
			reinterpret_cast<uintptr_t>(pPeb->Ldr) };

		if (!IsValidAddress(loaderAddress))
			return STATUS_INVALID_ADDRESS;

		PEB_LDR_DATA loaderData{};
		NTSTATUS status{ ReadVirtualMemoryNt<PEB_LDR_DATA>(
			processHandle,
			loaderAddress,
			loaderData) };

		if (!NT_SUCCESS(status))
			return status;

		uintptr_t firstLink{
			reinterpret_cast<uintptr_t>(
				loaderData.InLoadOrderModuleList.Flink) };

		if (!IsValidAddress(firstLink))
			return STATUS_INVALID_ADDRESS;

		uintptr_t entryAddress{
			firstLink - offsetof(LDR_DATA_TABLE_ENTRY, InLoadOrderLinks) };

		LDR_DATA_TABLE_ENTRY entry{};
		status = ReadVirtualMemoryNt(
			processHandle,
			entryAddress,
			entry);

		if (!NT_SUCCESS(status))
			return status;
		if (entry.DllBase == nullptr)
			return STATUS_UNSUCCESSFUL;

		*pModuleBaseAddress =
			reinterpret_cast<uintptr_t>(entry.DllBase);

		return status;
	}

	MUNINN_API NTSTATUS MUNINN_CALL
		GetWow64InfoNt(
			_In_ const HANDLE processHandle,
			_Out_ ULONG_PTR* const wow64Info) noexcept
	{
		if (!IsValidHandle(processHandle))
			return STATUS_INVALID_PARAMETER_1;
		if (wow64Info == nullptr)
			return STATUS_INVALID_PARAMETER_2;

		*wow64Info = 0ull;

		NTSTATUS status{ NtQueryInformationProcess(
			processHandle,
			ProcessWow64Information,
			wow64Info,
			sizeof(ULONG_PTR),
			nullptr) };

		return status;
	}

	MUNINN_API NTSTATUS MUNINN_CALL
		GetProcessModulesNt(
			_In_ const HANDLE processHandle,
			_In_ const PEB* const pPeb,
			_Out_writes_(bufferLength)
			LDR_DATA_TABLE_ENTRY* const pBuffer,
			_In_ const DWORD bufferLength,
			_Out_ DWORD* const pCopiedLength) noexcept
	{
		if (!IsValidHandle(processHandle))
			return STATUS_INVALID_PARAMETER_1;
		if (pPeb == nullptr)
			return STATUS_INVALID_PARAMETER_2;
		if (pBuffer == nullptr)
			return STATUS_INVALID_PARAMETER_3;
		if (pCopiedLength == nullptr)
			return STATUS_INVALID_PARAMETER_5;

		if (!pPeb->Ldr)
			return STATUS_UNSUCCESSFUL;

		*pBuffer = {};
		*pCopiedLength = 0ul;

		uintptr_t loaderAddress{
			reinterpret_cast<uintptr_t>(pPeb->Ldr) };
		if (!IsValidAddress(loaderAddress))
			return STATUS_INVALID_ADDRESS;

		PEB_LDR_DATA loaderData{};
		NTSTATUS status{ ReadVirtualMemoryNt<PEB_LDR_DATA>(
			processHandle,
			loaderAddress,
			loaderData) };

		if (!NT_SUCCESS(status))
			return status;
		if (!loaderData.InLoadOrderModuleList.Flink)
			return STATUS_UNSUCCESSFUL;

		uintptr_t listHead{
			loaderAddress + offsetof(PEB_LDR_DATA, InLoadOrderModuleList) };

		if (!IsValidAddress(listHead))
			return STATUS_INVALID_ADDRESS;

		uintptr_t currentLink{ reinterpret_cast<uintptr_t>(
			loaderData.InLoadOrderModuleList.Flink) };

		if (!IsValidAddress(currentLink))
			return STATUS_INVALID_ADDRESS;

		DWORD copied{ 0ull };
		DWORD sanityCounter{ 0ull };
		while (currentLink && currentLink != listHead)
		{
			if (++sanityCounter > MAX_MODULES)
				break;

			if (copied >= bufferLength)
				return STATUS_BUFFER_TOO_SMALL;

			// first remote module = fLink - ILOL offset
			uintptr_t entryAddress{
				currentLink - offsetof(LDR_DATA_TABLE_ENTRY, InLoadOrderLinks) };

			LDR_DATA_TABLE_ENTRY entry{};
			status = ReadVirtualMemoryNt<LDR_DATA_TABLE_ENTRY>(
				processHandle,
				entryAddress,
				entry);

			if (!NT_SUCCESS(status))
				break;

			pBuffer[copied++] = entry;

			uintptr_t next{ reinterpret_cast<uintptr_t>(
				entry.InLoadOrderLinks.Flink) };

			if (!IsValidAddress(next) || next == currentLink)
				break;

			currentLink = next;
		};

		*pCopiedLength = copied;
		return STATUS_SUCCESS;
	};

	MUNINN_API NTSTATUS MUNINN_CALL
		GetProcessThreadsNt(
			_In_ const HANDLE processHandle,
			_In_ const DWORD processId,
			_Out_writes_(bufferLength)
			SYSTEM_THREAD_INFORMATION* const pBuffer,
			_In_ const DWORD bufferLength,
			_Out_ DWORD* const pCopiedLength) noexcept
	{
		if (!IsValidHandle(processHandle))
			return STATUS_INVALID_PARAMETER_1;
		if (!IsValidProcessId(processId))
			return STATUS_INVALID_PARAMETER_2;
		if (pBuffer == nullptr)
			return STATUS_INVALID_PARAMETER_3;
		if (pCopiedLength == nullptr)
			return STATUS_INVALID_PARAMETER_5;

		*pBuffer = {};
		*pCopiedLength = 0ul;

		DWORD requiredBufferSize{};
		NTSTATUS status{ GetQSIBufferSizeNt(
			SystemProcessInformation,
			&requiredBufferSize) };

		if (!NT_SUCCESS(status))
			return status;

		BYTE* processInfoBuffer{
			new BYTE[requiredBufferSize] };

		status = NtQuerySystemInformation(
			SystemProcessInformation,
			processInfoBuffer,
			requiredBufferSize,
			nullptr);

		if (!NT_SUCCESS(status))
		{
			delete[] processInfoBuffer;
			return status;
		}

		PSYSTEM_PROCESS_INFORMATION processInfo{
			reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(processInfoBuffer) };

		DWORD threadCount{};
		if (!processInfo)
		{
			delete[] processInfoBuffer;
			return STATUS_UNSUCCESSFUL;
		}

		while (processInfo)
		{
			DWORD processInfoId{ static_cast<DWORD>(
				reinterpret_cast<uintptr_t>(processInfo->UniqueProcessId)) };

			if (processInfoId == processId)
			{
				threadCount = processInfo->NumberOfThreads;
				if (pCopiedLength)
					*pCopiedLength = threadCount;

				if (pBuffer)
				{
					uint32_t toCopy{
						std::min(bufferLength, threadCount) };

					for (uint32_t i{}; i < toCopy; ++i)
						pBuffer[i] = processInfo->Threads[i];
				}
				break;
			}
			if (processInfo->NextEntryOffset == 0)
				break;

			processInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(
				reinterpret_cast<BYTE*>(processInfo) +
				processInfo->NextEntryOffset);
		}
		delete[] processInfoBuffer;
		return STATUS_SUCCESS;
	}

	MUNINN_API NTSTATUS MUNINN_CALL
		GetProcessHandlesNt(
			_In_ const HANDLE processHandle,
			_In_ const DWORD processId,
			_Out_writes_(bufferLength)
			SYSTEM_HANDLE_TABLE_ENTRY_INFO* const pBuffer,
			_In_ const DWORD bufferLength,
			_Out_ DWORD* const pCopiedLength) noexcept
	{
		if (!IsValidHandle(processHandle))
			return STATUS_INVALID_PARAMETER_1;
		if (!IsValidProcessId(processId))
			return STATUS_INVALID_PARAMETER_2;
		if (pBuffer == nullptr)
			return STATUS_INVALID_PARAMETER_3;
		if (pCopiedLength == nullptr)
			return STATUS_INVALID_PARAMETER_5;

		*pBuffer = {};
		*pCopiedLength = 0ul;

		DWORD requiredBufferSize{};
		NTSTATUS status{ GetQSIBufferSizeNt(
			SystemHandleInformation,
			&requiredBufferSize) };
		requiredBufferSize += PAGE_SIZE;

		if (!NT_SUCCESS(status))
			return status;

		if (!requiredBufferSize)
			return STATUS_UNSUCCESSFUL;

		BYTE* handleInfoBuffer{
			new BYTE[requiredBufferSize] };
		status = NtQuerySystemInformation(
			SystemHandleInformation,
			handleInfoBuffer,
			requiredBufferSize,
			nullptr);

		if (!NT_SUCCESS(status))
		{
			delete[] handleInfoBuffer;
			return status;
		}

		PSYSTEM_HANDLE_INFORMATION handleInfo{
			reinterpret_cast<PSYSTEM_HANDLE_INFORMATION>(handleInfoBuffer) };
		if (!handleInfo)
		{
			delete[] handleInfoBuffer;
			return {};
		}

		DWORD copied{};
		DWORD total{};

		// AI generated, to be reviewed
		for (ULONG i{}; i < handleInfo->NumberOfHandles; ++i)
		{
			const SYSTEM_HANDLE_TABLE_ENTRY_INFO& entry =
				handleInfo->Handles[i];

			if ((DWORD)entry.UniqueProcessId != processId)
				continue;

			if (copied < bufferLength)
			{
				pBuffer[copied] = entry;
				++copied;
			}

			++total;
		}

		delete[] handleInfoBuffer;
		return STATUS_SUCCESS;
	}

	MUNINN_API NTSTATUS MUNINN_CALL
		GetProcessTokenStatisticsNt(
			_In_ const HANDLE tokenHandle,
			_Out_ TOKEN_STATISTICS* const pTokenStatistics) noexcept
	{
		if (!IsValidHandle(tokenHandle))
			return STATUS_INVALID_PARAMETER_1;
		if (pTokenStatistics == nullptr)
			return STATUS_INVALID_PARAMETER_2;

		*pTokenStatistics = {};

		// requiredBufferSize, the tarnished one
		DWORD requiredBufferSize{};
		NTSTATUS status{ NtQueryInformationToken(
			tokenHandle,
			static_cast<_TOKEN_INFORMATION_CLASS>(
				TokenStatistics), // phnt
			pTokenStatistics,
			sizeof(TOKEN_STATISTICS),
			&requiredBufferSize) };

		if (!NT_SUCCESS(status))
			*pTokenStatistics = {};

		return status;
	}

	MUNINN_API NTSTATUS MUNINN_CALL
		GetProcessTokenPriviligesNt(
			_In_ const HANDLE tokenHandle,
			_Out_writes_(bufferLength)
			LUID_AND_ATTRIBUTES* const pBuffer,
			_In_ const DWORD bufferLength,
			_Out_ DWORD* const pCopiedLength) noexcept
	{
		if (!IsValidHandle(tokenHandle))
			return STATUS_INVALID_PARAMETER_1;
		if (pBuffer == nullptr)
			return STATUS_INVALID_PARAMETER_2;
		if (pCopiedLength == nullptr)
			return STATUS_INVALID_PARAMETER_4;

		DWORD requiredBufferSize{};
		NTSTATUS status{ GetQITBufferSizeNt(
		tokenHandle,
		TokenPrivileges,
		&requiredBufferSize) };

		if (!NT_SUCCESS(status))
			return status;

		BYTE* privilegesBuffer{
			new BYTE[requiredBufferSize] };

		status = NtQueryInformationToken(
			tokenHandle,
			TokenPrivileges,
			privilegesBuffer,
			requiredBufferSize,
			&requiredBufferSize);

		if (!NT_SUCCESS(status))
		{
			delete[] privilegesBuffer;
			return status;
		}

		PTOKEN_PRIVILEGES privileges
		{ reinterpret_cast<PTOKEN_PRIVILEGES>(privilegesBuffer) };

		DWORD totalPrivileges{ privileges->PrivilegeCount };
		DWORD copied{ std::min(bufferLength, totalPrivileges) };

		for (DWORD i{}; i < copied; ++i)
		{
			pBuffer[i] = privileges->Privileges[i];
		}

		*pCopiedLength = totalPrivileges;
		delete[] privilegesBuffer;
		return STATUS_SUCCESS;
	}

	MUNINN_API NTSTATUS MUNINN_CALL
		GetProcessTokenSessionIdNt(
			_In_ const HANDLE tokenHandle,
			_Out_ DWORD* const pSessionId) noexcept
	{
		if (!IsValidHandle(tokenHandle))
			return STATUS_INVALID_PARAMETER_1;
		if (pSessionId == nullptr)
			return STATUS_INVALID_PARAMETER_2;

		*pSessionId = 0ul;

		DWORD requiredBufferSize{};
		NTSTATUS status{ NtQueryInformationToken(
			tokenHandle,
			TokenSessionId,
			pSessionId,
			sizeof(ULONG),
			&requiredBufferSize) };

		if (!NT_SUCCESS(status))
			*pSessionId = 0ul;

		return status;
	}

	/*
	BOOL GetProcessTokenPriviligeObjectsNt(const HANDLE tokenHandle, std::vector<Muninn::Object::PrivilegeEntry>& privileges)
	{
		if (!IsValidHandle(tokenHandle)) return FALSE;

		std::vector<LUID_AND_ATTRIBUTES> priviligesBuffer
		{ GetProcessTokenPriviligesNt(tokenHandle) };
		if (priviligesBuffer.empty()) return FALSE;

		for (LUID_AND_ATTRIBUTES privilege : priviligesBuffer)
		{
			Muninn::Object::PrivilegeEntry privilegeEntry{};
			privilegeEntry.TokenLuid = GetFullLuidNt(privilege.Luid);
			privilegeEntry.TokenAttributes = privilege.Attributes;
			privileges.push_back(privilegeEntry);
		}
		return TRUE;
	}
	*/


	/*
	BOOL GetProcessAccessTokenObjectNt(
		const HANDLE processHandle,
		const ACCESS_MASK accessMask,
		Muninn::Object::AccessToken& accessToken)
	{
		if (!IsValidHandle(processHandle)) return FALSE;

		HANDLE tokenHandle{ OpenProcessTokenHandleNt(processHandle, accessMask) };
		if (!IsValidHandle(tokenHandle)) return FALSE;

		TOKEN_STATISTICS statistics{
			GetProcessTokenStatisticsNt(tokenHandle) };
		if (!IsValidLuid(statistics.TokenId)) return FALSE;
		if (statistics.PrivilegeCount <= 0) return FALSE;

		DWORD sessionId{ GetProcessTokenSessionIdNt(tokenHandle) };
		if (!sessionId) return FALSE;

		std::vector<Muninn::Object::PrivilegeEntry> privileges{};
		if (!GetProcessTokenPriviligeObjectsNt(tokenHandle, privileges))
			return FALSE;

		accessToken.TokenPrivileges = privileges;
		accessToken.TokenId = GetFullLuidNt(statistics.TokenId);
		accessToken.AuthenticationId = GetFullLuidNt(statistics.AuthenticationId);
		accessToken.SessionId = sessionId;
		return TRUE;
	}
	*/
#pragma endregion
	/*
		BOOL GetProcessHandleObjectsNt(
		const HANDLE processHandle,
		const DWORD processId,
		std::vector<Muninn::Object::HandleEntry>& handles)
	{
		if (!IsValidHandle(processHandle)) return FALSE;
		if (!IsValidProcessId(processId)) return FALSE;

		DWORD requiredBufferSize{ GetQSIBufferSizeNt(SystemHandleInformation) + PAGE_SIZE };
		BYTE* handleInfoBuffer = new BYTE[requiredBufferSize];
		NTSTATUS ntStatus{ NtQuerySystemInformation(
				SystemHandleInformation,
				handleInfoBuffer,
				requiredBufferSize,
				nullptr) };

		if (!NT_SUCCESS(ntStatus))
		{
			delete[] handleInfoBuffer;
			return {};
		}

		PSYSTEM_HANDLE_INFORMATION handleInfo{ reinterpret_cast<PSYSTEM_HANDLE_INFORMATION>(handleInfoBuffer) };
		if (!handleInfo)
		{
			delete[] handleInfoBuffer;
			return {};
		}

		for (ULONG i{ 0 }; i < handleInfo->NumberOfHandles; ++i)
		{
			const SYSTEM_HANDLE_TABLE_ENTRY_INFO& sHandleInfo{ handleInfo->Handles[i] };
			if (static_cast<uintptr_t>(sHandleInfo.UniqueProcessId) != static_cast<uintptr_t>(processId))
				continue;

			Muninn::Object::HandleEntry handleEntry{};
			handleEntry.handleValue = reinterpret_cast<HANDLE>(sHandleInfo.HandleValue);
			handleEntry.typeName = GetObjectTypeNameNt(handleEntry.handleValue, processId);
			handleEntry.objectName = GetObjectNameNt(handleEntry.handleValue, processId);
			handleEntry.grantedAccess = sHandleInfo.GrantedAccess;

			// experimental
			if (handleEntry.typeName == L"Process")
				handleEntry.userHandleObjectType = Muninn::Object::UserHandleObjectType::Process;
			else if (handleEntry.typeName == L"Thread")
				handleEntry.userHandleObjectType = Muninn::Object::UserHandleObjectType::Thread;
			else if (handleEntry.typeName == L"Mutant")
				handleEntry.userHandleObjectType = Muninn::Object::UserHandleObjectType::Mutant;
			else if (handleEntry.typeName == L"Event")
				handleEntry.userHandleObjectType = Muninn::Object::UserHandleObjectType::Event;
			else if (handleEntry.typeName == L"Section")
				handleEntry.userHandleObjectType = Muninn::Object::UserHandleObjectType::Section;
			else if (handleEntry.typeName == L"Semaphore")
				handleEntry.userHandleObjectType = Muninn::Object::UserHandleObjectType::Semaphore;

			handles.push_back(handleEntry);
		}
		delete[] handleInfoBuffer;
		return TRUE;
	}


	std::vector<SYSTEM_EXTENDED_THREAD_INFORMATION> GetProcessThreadsExtendedNt(const HANDLE processHandle, const DWORD processId)
	{
		if (!IsValidHandle(processHandle)) return {};
		if (!IsValidProcessId(processId)) return {};

		const DWORD requiredSize{ GetQSIBufferSizeNt(SystemProcessInformation) };
		BYTE* processInfoBuffer = new BYTE[requiredSize];
		NTSTATUS status{ NtQuerySystemInformation(
			SystemProcessInformation,
			processInfoBuffer,
			requiredSize,
			nullptr) };

		if (!NT_SUCCESS(status))
		{
			delete[] processInfoBuffer;
			return {};
		}

		PSYSTEM_PROCESS_INFORMATION processInfo
		{ reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(processInfoBuffer) };
		if (!processInfo)
		{
			delete[] processInfoBuffer;
			return {};
		}

		std::vector<SYSTEM_EXTENDED_THREAD_INFORMATION> threads{};
		while (processInfo)
		{
			DWORD processInfoId{ static_cast<DWORD>(
				reinterpret_cast<uintptr_t>(processInfo->UniqueProcessId)) };

			if (processInfoId == processId)
			{
				for (ULONG i{ 0 }; i < processInfo->NumberOfThreads; ++i)
				{
					const SYSTEM_EXTENDED_THREAD_INFORMATION& sThreadInfo = processInfo->ThreadsEx[i];
					threads.push_back(sThreadInfo);
				} break;
			}
			if (processInfo->NextEntryOffset == 0) break;

			processInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(
				reinterpret_cast<BYTE*>(processInfo) +
				processInfo->NextEntryOffset);
		}
		delete[] processInfoBuffer;
		return threads;
	}

	BOOL GetProcessThreadObjectsNt(
		const HANDLE processHandle,
		const DWORD processId,
		std::vector<Muninn::Object::ThreadEntry>& threads)
	{
		if (!IsValidHandle(processHandle)) return FALSE;
		if (!IsValidProcessId(processId)) return FALSE;

		const DWORD requiredSize{ GetQSIBufferSizeNt(SystemProcessInformation) };
		BYTE* processInfoBuffer = new BYTE[requiredSize];
		NTSTATUS status{ NtQuerySystemInformation(
			SystemProcessInformation,
			processInfoBuffer,
			requiredSize,
			nullptr) };

		if (!NT_SUCCESS(status))
		{
			delete[] processInfoBuffer;
			return FALSE;
		}

		PSYSTEM_PROCESS_INFORMATION processInfo
		{ reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(processInfoBuffer) };
		if (!processInfo)
		{
			delete[] processInfoBuffer;
			return FALSE;
		}

		while (processInfo)
		{
			DWORD processInfoId{ static_cast<DWORD>(
				reinterpret_cast<uintptr_t>(processInfo->UniqueProcessId)) };

			if (processInfoId == processId)
			{
				for (ULONG i{ 0 }; i < processInfo->NumberOfThreads; ++i)
				{
					const SYSTEM_THREAD_INFORMATION& sThreadInfo{ processInfo->Threads[i] };
					Muninn::Object::ThreadEntry threadEntry{};
					threadEntry.kernelThreadStartAddress =
						reinterpret_cast<uintptr_t>(sThreadInfo.StartAddress);
					threadEntry.nativeThreadBasePriority =
						static_cast<KPRIORITY>(sThreadInfo.BasePriority);
					threadEntry.threadId =
						static_cast<DWORD>(reinterpret_cast<uintptr_t>(sThreadInfo.ClientId.UniqueThread));
					threadEntry.threadOwnerProcessId = processId;
					threads.push_back(threadEntry);
				} break;
			}
			if (processInfo->NextEntryOffset == 0) break;

			processInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(
				reinterpret_cast<BYTE*>(processInfo) +
				processInfo->NextEntryOffset);
		}
		delete[] processInfoBuffer;
		return TRUE;
	}

		BOOL GetProcessThreadObjectsExtendedNt(
			const HANDLE processHandle,
			const DWORD processId,
			std::vector<Muninn::Object::ThreadEntry>& threads)
		{
			if (!IsValidHandle(processHandle)) return FALSE;
			if (!IsValidProcessId(processId)) return FALSE;

			const DWORD requiredSize{ GetQSIBufferSizeNt(SystemExtendedProcessInformation) };
			BYTE* processInfoBuffer = new BYTE[requiredSize];
			NTSTATUS status{ NtQuerySystemInformation(
				SystemExtendedProcessInformation,
				processInfoBuffer,
				requiredSize,
				nullptr) };

			if (!NT_SUCCESS(status))
			{
				delete[] processInfoBuffer;
				return FALSE;
			}

			PSYSTEM_PROCESS_INFORMATION processInfo
			{ reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(processInfoBuffer) };
			if (!processInfo)
			{
				delete[] processInfoBuffer;
				return FALSE;
			}

			while (processInfo)
			{
				DWORD processInfoId{ static_cast<DWORD>(
					reinterpret_cast<uintptr_t>(processInfo->UniqueProcessId)) };

				if (processInfoId == processId)
				{
					for (ULONG i{ 0 }; i < processInfo->NumberOfThreads; ++i)
					{
						const SYSTEM_THREAD_INFORMATION& sThreadInfo{ processInfo->Threads[i] };
						const SYSTEM_EXTENDED_THREAD_INFORMATION& sThreadExInfo{ processInfo->ThreadsEx[i] };
						Muninn::Object::ThreadEntry threadEntry{};
						threadEntry.kernelThreadStartAddress =
							reinterpret_cast<uintptr_t>(sThreadInfo.StartAddress);
						threadEntry.win32ThreadStartAddress =
							reinterpret_cast<uintptr_t>(sThreadExInfo.Win32StartAddress);
						threadEntry.tebBaseAddress =
							reinterpret_cast<uintptr_t>(sThreadExInfo.TebBase);
						threadEntry.nativeThreadBasePriority =
							static_cast<KPRIORITY>(sThreadInfo.BasePriority);
						threadEntry.threadId =
							static_cast<DWORD>(
								reinterpret_cast<uintptr_t>(sThreadInfo.ClientId.UniqueThread));
						threadEntry.threadOwnerProcessId = processId;
						threads.push_back(threadEntry);
					} break;
				}
				if (processInfo->NextEntryOffset == 0) break;

				processInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(
					reinterpret_cast<BYTE*>(processInfo) +
					processInfo->NextEntryOffset);
			}
			delete[] processInfoBuffer;
			return TRUE;
		}

		BOOL GetProcessInformationObjectNt(const HANDLE processHandle, Muninn::Object::ProcessEntry& processEntry)
	{
		if (!IsValidHandle(processHandle)) return FALSE;

		PROCESS_EXTENDED_BASIC_INFORMATION processInfo{};
		NTSTATUS status{ NtQueryInformationProcess(
			processHandle,
			ProcessBasicInformation,
			&processInfo,
			sizeof(PROCESS_EXTENDED_BASIC_INFORMATION),
			nullptr) };

		if (!NT_SUCCESS(status)) return FALSE;

		processEntry.pebBaseAddress =
			reinterpret_cast<uintptr_t>(processInfo.BasicInfo.PebBaseAddress);
		processEntry.processId =
			static_cast<DWORD>(
				reinterpret_cast<uintptr_t>(processInfo.BasicInfo.UniqueProcessId));
		processEntry.parentProcessId =
			static_cast<DWORD>(
				reinterpret_cast<uintptr_t>(processInfo.BasicInfo.InheritedFromUniqueProcessId));
		processEntry.isProtectedProcess = processInfo.IsProtectedProcess;
		processEntry.isWow64Process = processInfo.IsWow64Process;
		processEntry.isBackgroundProcess = processInfo.IsBackground;
		processEntry.isSecureProcess = processInfo.IsSecureProcess;
		processEntry.isSubsystemProcess = processInfo.IsSubsystemProcess;
		return TRUE;
	}

	BOOL GetProcessInformationObjectExtendedNt(
		const HANDLE processHandle,
		const DWORD processId,
		Muninn::Object::ProcessEntry& processEntry)
	{
		if (!IsValidHandle(processHandle)) return FALSE;
		if (!IsValidProcessId(processId)) return FALSE;

		const DWORD requiredBufferSize{ GetQSIBufferSizeNt(SystemProcessInformation) };
		BYTE* systemInfoBuffer = new BYTE[requiredBufferSize];
		NTSTATUS qsiStatus{ NtQuerySystemInformation(
			SystemProcessInformation,
			systemInfoBuffer,
			requiredBufferSize,
			nullptr) };

		if (!NT_SUCCESS(qsiStatus))
		{
			delete[] systemInfoBuffer;
			return FALSE;
		}

		PROCESS_EXTENDED_BASIC_INFORMATION processInfo{};
		NTSTATUS qipStatus{ NtQueryInformationProcess(
			processHandle,
			ProcessBasicInformation,
			&processInfo,
			sizeof(PROCESS_EXTENDED_BASIC_INFORMATION),
			nullptr) };

		if (!NT_SUCCESS(qipStatus))
		{
			delete[] systemInfoBuffer;
			return FALSE;
		}

		PSYSTEM_PROCESS_INFORMATION systemInfo
		{ reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(systemInfoBuffer) };
		while (systemInfo)
		{
			DWORD uniqueProcessId
			{ static_cast<DWORD>(reinterpret_cast<uintptr_t>(systemInfo->UniqueProcessId)) };
			if (uniqueProcessId == processId)
			{
				processEntry.processName = (systemInfo->ImageName.Buffer) ?
					systemInfo->ImageName.Buffer :
					L"";
				processEntry.NativeImageFileName = GetImageFileNameNt(processHandle);
				processEntry.architectureType = GetArchitectureTypeNt(processHandle);
				processEntry.pebBaseAddress =
					reinterpret_cast<uintptr_t>(processInfo.BasicInfo.PebBaseAddress);
				processEntry.processId =
					static_cast<DWORD>(
						reinterpret_cast<uintptr_t>(processInfo.BasicInfo.UniqueProcessId));
				processEntry.parentProcessId =
					static_cast<DWORD>(
						reinterpret_cast<uintptr_t>(processInfo.BasicInfo.InheritedFromUniqueProcessId));
				processEntry.isProtectedProcess = processInfo.IsProtectedProcess;
				processEntry.isWow64Process = processInfo.IsWow64Process;
				processEntry.isBackgroundProcess = processInfo.IsBackground;
				processEntry.isSecureProcess = processInfo.IsSecureProcess;
				processEntry.isSubsystemProcess = processInfo.IsSubsystemProcess;
				break;
			}
		}
		return TRUE;
	}


	BOOL GetProcessModuleObjectsNt(
		const HANDLE processHandle,
		const DWORD processId,
		const PEB& peb,
		std::vector<Muninn::Object::ModuleEntry>& modules)
	{
		if (!IsValidHandle(processHandle)) return FALSE;
		if (!IsValidProcessId(processId)) return FALSE;
		if (!peb.Ldr) return FALSE;

		uintptr_t loaderAddress{ reinterpret_cast<uintptr_t>(peb.Ldr) };
		if (!IsValidAddress(loaderAddress)) return FALSE;

		PEB_LDR_DATA loaderData{};
		if (!NT_SUCCESS(ReadVirtualMemoryNt<PEB_LDR_DATA>(processHandle, loaderAddress, loaderData))) return {};
		if (!loaderData.InLoadOrderModuleList.Flink) return FALSE;

		uintptr_t listHead{ loaderAddress + offsetof(PEB_LDR_DATA, InLoadOrderModuleList) };
		if (!IsValidAddress(listHead)) return FALSE;

		uintptr_t currentLink{ reinterpret_cast<uintptr_t>(loaderData.InLoadOrderModuleList.Flink) };
		if (!IsValidAddress(currentLink)) return FALSE;

		size_t sanityCounter{ 0 };
		while (currentLink && currentLink != listHead)
		{
			if (++sanityCounter > MAX_MODULES)
				break;

			// first remote module = fLink - ILOL offset
			uintptr_t entryAddress{ currentLink - offsetof(LDR_DATA_TABLE_ENTRY, InLoadOrderLinks) };
			LDR_DATA_TABLE_ENTRY entry{};
			if (!NT_SUCCESS(ReadVirtualMemoryNt<LDR_DATA_TABLE_ENTRY>(processHandle, entryAddress, entry)))
				break;

			Muninn::Object::ModuleEntry moduleEntry{};
			moduleEntry.moduleName = GetRemoteUnicodeStringNt(processHandle, entry.BaseDllName);
			moduleEntry.modulePath = GetRemoteUnicodeStringNt(processHandle, entry.FullDllName);
			moduleEntry.moduleEntryPoint
				= reinterpret_cast<uintptr_t>(entry.EntryPoint);
			moduleEntry.moduleBaseAddress
				= reinterpret_cast<uintptr_t>(entry.DllBase);
			moduleEntry.parentDllBaseAddress
				= reinterpret_cast<uintptr_t>(entry.ParentDllBase);
			moduleEntry.moduleImageSize = entry.SizeOfImage;
			moduleEntry.processId = processId;
			moduleEntry.tlsIndex = entry.TlsIndex;
			modules.push_back(std::move(moduleEntry));

			uintptr_t next =
				reinterpret_cast<uintptr_t>(entry.InLoadOrderLinks.Flink);
			if (!IsValidAddress(next) || next == currentLink) break;
			else currentLink = next;
		};
		return TRUE;
	};

	std::vector<Muninn::Object::ProcessEntry> WindowsProviderNt::QueryProcesses()
	{
		const DWORD requiredSize{ Muninn::Service::GetQSIBufferSizeNt(SystemProcessInformation) };
		std::unique_ptr<BYTE[]> pBuffer(new BYTE[requiredSize]);
		NTSTATUS systemInfoStatus{ NtQuerySystemInformation(
			SystemProcessInformation,
			pBuffer.get(),
			requiredSize,
			nullptr) };

		if (!NT_SUCCESS(systemInfoStatus)) return {};

		std::vector<Muninn::Object::ProcessEntry> processList{};
		PSYSTEM_PROCESS_INFORMATION processInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(pBuffer.get());
		while (processInfo)
		{
			Muninn::Object::ProcessEntry pEntry{};
			pEntry.processId = static_cast<DWORD>(reinterpret_cast<uintptr_t>(processInfo->UniqueProcessId));
			pEntry.parentProcessId = static_cast<DWORD>(reinterpret_cast<uintptr_t>(processInfo->InheritedFromUniqueProcessId));
			pEntry.processName = (processInfo->ImageName.Buffer) ? processInfo->ImageName.Buffer : L"";
			QueryModuleBaseAddress(pEntry.processId, pEntry.processName);

			ACCESS_MASK accessMasks[]{
				PROCESS_ALL_ACCESS,
				PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
				PROCESS_QUERY_LIMITED_INFORMATION
			};

			HANDLE hProc{};
			for (ACCESS_MASK accessMask : accessMasks)
			{
				hProc = Muninn::Service::OpenHandleNt(pEntry.processId, accessMask);
				if (Muninn::Service::IsValidHandle(hProc)) break;
				else return{};
			}

			GetExtendedProcessInfo(hProc);
			GetImageFileNameNt(hProc);
			QueryPriorityClassNt(hProc);
			QueryArchitectureNt(hProc);

			// Threads
			for (ULONG i = 0; i < processInfo->NumberOfThreads; ++i)
			{
				Muninn::Object::ThreadEntry threadEntry{};
				const SYSTEM_THREAD_INFORMATION& sThreadInfo = processInfo->Threads[i];

				threadEntry.structureSize = sizeof(SYSTEM_THREAD_INFORMATION);
				threadEntry.threadId = static_cast<DWORD>(
					reinterpret_cast<uintptr_t>(sThreadInfo.ClientId.UniqueThread));
				threadEntry.ownerProcessId = pEntry.processId;
				threadEntry.basePriority = sThreadInfo.BasePriority;
				threadEntry.startAddress = sThreadInfo.StartAddress;
				threadEntry.threadState = sThreadInfo.ThreadState;
				pEntry.threads.push_back(threadEntry);
			}
			processList.push_back(pEntry);
			Muninn::Service::CloseHandleNt(hProc);

			// Advance to next process (ALWAYS)
			if (processInfo->NextEntryOffset)
			{
				processInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(
					reinterpret_cast<BYTE*>(processInfo) + processInfo->NextEntryOffset);
			}
			else break;
		}
		return processList;
	}*/
}