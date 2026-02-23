#pragma once
#include <Windows.h>
#include <string>
#include "ntdll.h"

namespace Corvus::Data
{
	DWORD GetQSIBufferSizeNt(const SYSTEM_INFORMATION_CLASS sInfoClass);
	std::wstring ReadRemoteUnicodeStringNt(HANDLE hProcess, const UNICODE_STRING& unicodeString);

	template <typename T>
	NTSTATUS ReadVirtualMemoryNt(HANDLE hProc, uintptr_t baseAddress, T& out)
	{
		return NtReadVirtualMemory(
			hProc,
			reinterpret_cast<PVOID>(baseAddress),
			&out,
			sizeof(T),
			nullptr);
	}
}