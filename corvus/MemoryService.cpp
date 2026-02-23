#include "MemoryService.h"
#include "ntdll.h"
#pragma comment(lib, "ntdll.lib")

namespace Corvus::Data
{
	bool IsValidProcessId(const DWORD processId) noexcept
	{
		return processId % 4 == 0;
	}

	bool IsValidAddress(const DWORD address) noexcept
	{
		return address != ERROR_INVALID_ADDRESS;
	}

	bool IsValidHandle(const HANDLE handle) noexcept
	{
		return (handle != nullptr &&
			handle != reinterpret_cast<HANDLE>(-1) &&
			handle != INVALID_HANDLE_VALUE);
	}

	HANDLE OpenProcessHandle(const DWORD processId, const ACCESS_MASK accessMask)
	{
		OBJECT_ATTRIBUTES objectAttributes{};
		objectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);

		CLIENT_ID clientId{};
		clientId.UniqueProcess = reinterpret_cast<HANDLE>(processId);
		clientId.UniqueThread = nullptr;

		HANDLE pHandle{ nullptr };
		NTSTATUS status{ NtOpenProcess(&pHandle, accessMask, &objectAttributes, &clientId) };
		if (NT_SUCCESS(status) && IsValidHandle(pHandle)) return pHandle;
		else return nullptr;
	}

	BOOL CloseProcessHandle(HANDLE handle)
	{
		return NT_SUCCESS(NtClose(handle));
	}
}