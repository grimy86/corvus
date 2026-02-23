#pragma once
#include "WindowsStructures.h"

namespace Corvus::Data
{
	PROCESS_EXTENDED_BASIC_INFORMATION QueryExtendedProcessInfo(HANDLE hProcess);
	std::wstring QueryImageFilePathNt(HANDLE hProcess);
	uintptr_t QueryModuleBaseAddress(DWORD processId, const std::wstring& processName);
	Corvus::Object::UserProcessBasePriorityClass QueryPriorityClassNt(HANDLE hProcess);
	Corvus::Object::ArchitectureType QueryArchitectureNt(HANDLE hProcess);
	std::wstring QueryObjectNameNt(HANDLE hObject, DWORD processId);
	std::wstring QueryObjectTypeNameNt(HANDLE hObject, DWORD processId);
	BOOL QueryProcessInformation(Corvus::Object::ProcessEntry& processEntry);
	BOOL QueryModuleInformation(Corvus::Object::ProcessEntry& processEntry);
	BOOL QueryThreadInformation(Corvus::Object::ProcessEntry& processEntry);
	BOOL QueryHandleInformation(Corvus::Object::ProcessEntry& processEntry);
	std::vector<Corvus::Object::ModuleEntry> QueryModules(Corvus::Object::ProcessObject& process);
	std::vector<Corvus::Object::ThreadEntry> QueryThreads(Corvus::Object::ProcessObject& process);
	std::vector<Corvus::Object::HandleEntry> QueryHandles(Corvus::Object::ProcessObject& process);
}