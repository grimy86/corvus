#pragma once
#include <Windows.h>

namespace Corvus::Data
{
	bool IsValidProcessId(const DWORD processId) noexcept;
	bool IsValidHandle(const HANDLE processHandle) noexcept;
	bool IsValidAddress(const DWORD moduleBaseAddress) noexcept;

	HANDLE OpenProcessHandle(const DWORD processId, const ACCESS_MASK accessMask);
	BOOL CloseProcessHandle(HANDLE handle);
}