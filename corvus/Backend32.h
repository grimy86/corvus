#pragma once
#include "IProcessBackend.h"

namespace Corvus::Backend
{
	class Backend32 : public IProcessBackend
	{
	private:
		Backend32() = delete;

		std::wstring QueryImageFilePath(HANDLE hProcess);
		static uintptr_t QueryModuleBaseAddress(DWORD processId, const std::wstring& processName);
		static Corvus::Process::PriorityClass QueryPriorityClass(HANDLE hProcess);
		static bool QueryVisibleWindow(DWORD processId);
		static Corvus::Process::ArchitectureType QueryArchitecture(HANDLE hProcess, BOOL& isWow64);

	public:
		~Backend32() override = default;

		HANDLE OpenBackendHandle(const DWORD processId, const ACCESS_MASK accessMask) override;
		BOOL CloseBackendHandle(HANDLE handle) override;
		Corvus::Process::ProcessEntry QueryProcessInfo(HANDLE hProcess, DWORD processId) override;
		std::vector<Corvus::Process::ModuleEntry> QueryModules(const Corvus::Process::WindowsProcess& Process) override;
		std::vector<Corvus::Process::ThreadEntry> QueryThreads(const Corvus::Process::WindowsProcess& Process) override;
		std::vector<Corvus::Process::HandleEntry> QueryHandles(const Corvus::Process::WindowsProcess& Process) override;

		static bool QuerySeDebugPrivilege32(HANDLE hProcess);
		static int QueryThreadPriority32(HANDLE hThread);
	};
}