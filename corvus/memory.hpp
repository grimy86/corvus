#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include <string>
#include "converter.hpp"

namespace corvus::memory
{
	// Processes
	uintptr_t GetModuleBaseAddress(const DWORD& processId, const std::string& moduleName);

	// External
	void PatchExecution(HANDLE processHandle, DWORD destination, BYTE* value, unsigned int size);
	void NopExecution(HANDLE processHandle, DWORD destination, unsigned int size);
	DWORD FindDMAAddy(HANDLE processHandle, DWORD ptr, std::vector<DWORD> offsets);

	// Internal
	void PatchExecutionI(DWORD destination, BYTE* value, unsigned int size);
	void NopExecutionI(DWORD destination, unsigned int size);
	DWORD FindDMAAddyI(DWORD ptr, std::vector<DWORD> offsets);

	// Validators
	bool IsValidProcId(const DWORD procId);
	bool IsValidModuleBaseAddress(const DWORD moduleBaseAddr);
	bool IsValidHandle(const HANDLE handle);

	// Templates
	template <typename T>
	T ReadFromMemory(const HANDLE processHandle, const uintptr_t readAddress)
	{
		T returnValue{};

		ReadProcessMemory(
			processHandle,
			reinterpret_cast<LPCVOID>(readAddress),
			reinterpret_cast<LPVOID>(&returnValue),
			sizeof(returnValue),
			nullptr
		);

		return returnValue;
	}

	template <typename T>
	bool WriteToMemory(const HANDLE processHandle, const uintptr_t writeAddress, const T& writeValue)
	{
		return static_cast<bool>(WriteProcessMemory(
			processHandle,
			reinterpret_cast<LPVOID>(writeAddress),
			reinterpret_cast<LPCVOID>(&writeValue),
			sizeof(writeValue),
			nullptr
		));
	}
}