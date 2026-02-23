#pragma once
#include <Windows.h>

namespace Corvus::Data
{
	static bool IsValidProcessId(const DWORD processId) noexcept;
	static bool IsValidHandle(const HANDLE processHandle) noexcept;
	static bool IsValidAddress(const DWORD moduleBaseAddress) noexcept;

	static HANDLE OpenProcessHandle(const DWORD processId, const ACCESS_MASK accessMask);
	static BOOL CloseProcessHandle(HANDLE handle);
}