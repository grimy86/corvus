#pragma once
#include "WindowsStructures.h"
#include <ProcessSnapshot.h>

namespace Muninn::Data
{
#pragma region WRITE
	HANDLE OpenProcessHandle32(const DWORD processId, const ACCESS_MASK accessMask);
	BOOL CloseHandle32(const HANDLE handle);
	HANDLE OpenTokenHandle32(const HANDLE processHandle, const ACCESS_MASK accessMask);
	BOOL SetSeDebugPrivilege32();
	BOOL SetSeDebugPrivilege32(const HANDLE tokenHandle);
	BOOL SetThreadPriority32(const DWORD priorityClass);
	BOOL SetThreadSuspended32(const DWORD threadId);
	BOOL SetThreadResumed32(const DWORD threadId);
#pragma endregion

#pragma region READ
	int GetThreadPriority32(HANDLE threadHandle);

	DWORD GetTokenInfoBufferSize32(
		const HANDLE tokenHandle,
		const _TOKEN_INFORMATION_CLASS infoClass);

	BOOL GetSeDebugPrivilege32(const HANDLE tokenHandle);

	PROCESSENTRY32W GetProcessInformation32(const DWORD processId);

	BOOL GetProcessInformationObject32(
		const DWORD processId,
		Muninn::Object::ProcessEntry& processEntry);

	std::wstring GetImageFileName32(const HANDLE hProcess);

	uintptr_t GetModuleBaseAddress32(const DWORD processId, const std::wstring& processName);

	BOOL GetWindowVisibility32(const DWORD processId);

	BOOL GetProcessArchitecture32(
		const HANDLE processHandle,
		Muninn::Object::ArchitectureType& architectureType,
		BOOL& isWow64);

	std::vector<std::pair<MODULEENTRY32W, MODULEINFO>> GetProcessModules32(
		const HANDLE processHandle,
		const DWORD processId);

	BOOL GetProcessModuleObjects32(
		const HANDLE processHandle,
		const DWORD processId,
		std::vector<Muninn::Object::ModuleEntry>& modules);

	std::vector<THREADENTRY32> GetProcessThreads32(
		const HANDLE processHandle,
		const DWORD processId);

	BOOL GetProcessThreadObjects32(
		const HANDLE processHandle,
		const DWORD processId,
		std::vector<Muninn::Object::ThreadEntry>& threads);

	std::vector<PSS_HANDLE_ENTRY> GetProcessHandles32(
		const HANDLE processHandle,
		const DWORD processId);

	BOOL GetProcessHandleObjects32(
		const HANDLE processHandle,
		const DWORD processId,
		std::vector<Muninn::Object::HandleEntry>& handles);
#pragma endregion
}