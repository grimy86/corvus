#pragma once
#include "MemoryStructures.h"
#include <Windows.h>
#include <string>

namespace Corvus::Memory
{
	// Validators
	bool IsValidProcessId(const DWORD processId) noexcept;
	bool IsValidHandle(const HANDLE processHandle) noexcept;
	bool IsValidAddress(const DWORD moduleBaseAddress) noexcept;

	BOOL Inject(DWORD processId, const std::wstring& dllPath);

	bool InstallInlineHook(void* originalFunctionToHook,
		void* hookFunction,
		int opcodeLength,
		HookInfo& outHookInfo);
}