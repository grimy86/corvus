#pragma once
#include "WindowsStructures.h"

namespace Corvus::Data
{
#pragma region WRITE
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
	BOOL WriteProcessMemory32(const HANDLE processHandle, const uintptr_t writeAddress, const T& writeValue)
	{
		return WriteProcessMemory(
			processHandle,
			reinterpret_cast<LPVOID>(writeAddress),
			reinterpret_cast<LPCVOID>(&writeValue),
			sizeof(writeValue),
			nullptr);
	}
#pragma endregion

#pragma region READ
	template <typename T>
	BOOL ReadProcessMemory32(const HANDLE processHandle, const uintptr_t readAddress)
	{
		T returnValue{};
		return ReadProcessMemory(
			processHandle,
			reinterpret_cast<LPCVOID>(readAddress),
			reinterpret_cast<LPVOID>(&returnValue),
			sizeof(returnValue),
			nullptr);
		return returnValue;
	}

	std::wstring QueryImageFilePath(HANDLE hProcess);
	uintptr_t QueryModuleBaseAddress(DWORD processId, const std::wstring& processName);
	bool QueryVisibleWindow(DWORD processId);
	Corvus::Object::ArchitectureType QueryArchitecture(HANDLE hProcess, BOOL& isWow64);
	BOOL QueryProcessInformation(Corvus::Object::ProcessEntry& processEntry);
	BOOL QueryModuleInformation(Corvus::Object::ProcessEntry& processEntry);
	BOOL QueryThreadInformation(Corvus::Object::ProcessEntry& processEntry);
	BOOL QueryHandleInformation(Corvus::Object::ProcessEntry& processEntry);
	std::vector<Corvus::Object::ModuleEntry> QueryModules(Corvus::Object::ProcessObject& process);
	std::vector<Corvus::Object::ThreadEntry> QueryThreads(Corvus::Object::ProcessObject& process);
	std::vector<Corvus::Object::HandleEntry> QueryHandles(Corvus::Object::ProcessObject& process);
	bool QuerySeDebugPrivilege32(HANDLE hProcess);
	int QueryThreadPriority32(HANDLE hThread);
#pragma endregion
}