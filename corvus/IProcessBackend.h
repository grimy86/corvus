#pragma once
#include "WindowsStructures.h"
#include <vector>

namespace Corvus::Process
{
	class WindowsProcess;
}

namespace Corvus::Backend
{
	class IProcessBackend
	{
	protected:
		virtual std::wstring QueryImageFilePath(HANDLE hProcess) = 0;
		virtual uintptr_t QueryModuleBaseAddress(DWORD processId, const std::wstring& processName) = 0;
		virtual Corvus::Process::PriorityClass QueryPriorityClass(HANDLE hProcess) = 0;
		virtual bool QueryVisibleWindow(DWORD processId) = 0;
		virtual Corvus::Process::ArchitectureType QueryArchitecture(HANDLE hProcess, BOOL& isWow64) = 0;

	public:
		IProcessBackend() = default;
		virtual ~IProcessBackend() = default;

		virtual HANDLE OpenBackendHandle(const DWORD processId, const ACCESS_MASK accessMask) = 0;
		virtual BOOL CloseBackendHandle(HANDLE handle) = 0;
		virtual std::vector<Corvus::Process::ProcessEntry> QueryProcesses() = 0;
		virtual Corvus::Process::ProcessEntry QueryProcessInfo(HANDLE hProcess, DWORD processId) = 0;
		virtual std::vector<Corvus::Process::ModuleEntry> QueryModules(const Corvus::Process::WindowsProcess& Process) = 0;
		virtual std::vector<Corvus::Process::ThreadEntry> QueryThreads(const Corvus::Process::WindowsProcess& Process) = 0;
		virtual std::vector<Corvus::Process::HandleEntry> QueryHandles(const Corvus::Process::WindowsProcess& Process) = 0;
	};
}