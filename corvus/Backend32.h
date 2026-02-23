#pragma once
#include "IWindowsBackend.h"

namespace Corvus::Data
{
	class Backend32 final : public IWindowsBackend
	{
	private:
		std::wstring QueryImageFilePath(HANDLE hProcess);
		static uintptr_t QueryModuleBaseAddress(DWORD processId, const std::wstring& processName);
		static Corvus::Object::UserProcessBasePriorityClass QueryPriorityClass(HANDLE hProcess);
		static bool QueryVisibleWindow(DWORD processId);
		static Corvus::Object::ArchitectureType QueryArchitecture(HANDLE hProcess, BOOL& isWow64);

	public:
		Backend32() = default;
		~Backend32() override = default;

		BOOL QueryProcessInformation(Corvus::Object::ProcessEntry& processEntry) override;
		BOOL QueryModuleInformation(Corvus::Object::ProcessEntry& processEntry) override;
		BOOL QueryThreadInformation(Corvus::Object::ProcessEntry& processEntry) override;
		BOOL QueryHandleInformation(Corvus::Object::ProcessEntry& processEntry) override;
		std::vector<Corvus::Object::ModuleEntry> QueryModules(Corvus::Object::ProcessObject& process) override;
		std::vector<Corvus::Object::ThreadEntry> QueryThreads(Corvus::Object::ProcessObject& process) override;
		std::vector<Corvus::Object::HandleEntry> QueryHandles(Corvus::Object::ProcessObject& process) override;

		static bool QuerySeDebugPrivilege32(HANDLE hProcess);
		static int QueryThreadPriority32(HANDLE hThread);
	};
}