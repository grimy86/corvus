#pragma once
#include <Windows.h>

namespace Muninn::Data
{
	bool IsValidProcessId(const DWORD processId) noexcept;
	bool IsValidHandle(const HANDLE processHandle) noexcept;
	bool IsValidAddress(const DWORD moduleBaseAddress) noexcept;
	bool IsValidLuid(const LUID luid) noexcept;
}