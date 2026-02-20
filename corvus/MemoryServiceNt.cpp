#include "MemoryServiceNt.h"
#include "MemoryService.h"
#pragma comment(lib, "ntdll.lib")

namespace Corvus::Memory
{
	HANDLE OpenHandleNt(const DWORD processId, const ACCESS_MASK accessMask)
	{
		OBJECT_ATTRIBUTES objectAttributes{};
		objectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);

		CLIENT_ID clientId{};
		clientId.UniqueProcess = reinterpret_cast<HANDLE>(processId);
		clientId.UniqueThread = nullptr;

		HANDLE pHandle{ nullptr };
		NTSTATUS status{ NtOpenProcess(&pHandle, accessMask, &objectAttributes, &clientId) };
		if (NT_SUCCESS(status) && IsValidHandle(pHandle))
		{
			return pHandle;
		}
		else return nullptr;
	}

	BOOL CloseHandleNt(HANDLE handle) { return NT_SUCCESS(NtClose(handle)); }

	DWORD GetQSIBufferSizeNt(const SYSTEM_INFORMATION_CLASS sInfoClass)
	{
		DWORD requiredBufferSize{};
		BYTE buffer[0x20];

		NTSTATUS ntStatus{ NtQuerySystemInformation(
			sInfoClass,
			buffer,
			sizeof(buffer),
			&requiredBufferSize) };

		return requiredBufferSize;
	}

	std::wstring ReadRemoteUnicodeStringNt(HANDLE hProcess, const UNICODE_STRING& unicodeString)
	{
		if (!unicodeString.Buffer || !unicodeString.Length) return {};
		std::wstring s(unicodeString.Length / sizeof(wchar_t), L'\0');

		NtReadVirtualMemory(
			hProcess,
			reinterpret_cast<PVOID>(unicodeString.Buffer),
			s.data(),
			unicodeString.Length,
			nullptr);

		return s;
	}
}

