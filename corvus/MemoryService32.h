#pragma once
#include <Windows.h>
#include <vector>

namespace Corvus::Data
{
	BOOL SuspendThread32(const DWORD threadId);
	BOOL ResumeThread32(const DWORD threadId);
	BOOL EnableSeDebugPrivilege32();
	BOOL EnableSeDebugPrivilege32(const DWORD processId);
	BOOL SetThreadPriority32(int priorityMask);
	void PatchExecutionExt32(HANDLE processHandle, DWORD destination, BYTE* value, unsigned int size);
	void PatchExecutionInt32(DWORD destination, BYTE* value, unsigned int size);
	void NopExecutionExt32(HANDLE processHandle, DWORD destination, unsigned int size);
	void NopExecutionInt32(DWORD destination, unsigned int size);
	DWORD FindDMAAddyExt32(HANDLE processHandle, DWORD ptr, std::vector<DWORD> offsets);
	DWORD FindDMAAddyInt32(DWORD ptr, std::vector<DWORD> offsets);

	template <typename T>
	bool ReadProcessMemoryExt32(const HANDLE processHandle, const uintptr_t readAddress)
	{
		T returnValue{};
		return static_cast<bool>(ReadProcessMemory(
			processHandle,
			reinterpret_cast<LPCVOID>(readAddress),
			reinterpret_cast<LPVOID>(&returnValue),
			sizeof(returnValue),
			nullptr));
		return returnValue;
	}

	template <typename T>
	bool WriteProcessMemoryExt32(const HANDLE processHandle, const uintptr_t writeAddress, const T& writeValue)
	{
		return static_cast<bool>(WriteProcessMemory(
			processHandle,
			reinterpret_cast<LPVOID>(writeAddress),
			reinterpret_cast<LPCVOID>(&writeValue),
			sizeof(writeValue),
			nullptr));
	}
}