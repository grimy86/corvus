#pragma once
#include "WindowsStructures.h"

namespace Corvus::Data
{
	std::wstring QueryImageFilePath(HANDLE hProcess);
	uintptr_t QueryModuleBaseAddress(DWORD processId, const std::wstring& processName);
	Corvus::Object::UserProcessBasePriorityClass QueryPriorityClass(HANDLE hProcess);
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
}