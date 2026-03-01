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

	bool IsValidLuid(const LUID luid)
	{
		return (luid.HighPart != 0 && luid.LowPart != 0);
	}
}