#pragma once
#include "IWindowsBackend.h"

namespace Corvus::Data
{
	class BackendNt final : public IWindowsBackend
	{
	private:
		static PROCESS_EXTENDED_BASIC_INFORMATION QueryExtendedProcessInfo(HANDLE hProcess);
		static std::wstring QueryImageFilePathNt(HANDLE hProcess);
		static uintptr_t QueryModuleBaseAddress(DWORD processId, const std::wstring& processName);
		static Corvus::Object::UserProcessBasePriorityClass QueryPriorityClassNt(HANDLE hProcess);
		static Corvus::Object::ArchitectureType QueryArchitectureNt(HANDLE hProcess);
		static std::wstring QueryObjectNameNt(HANDLE hObject, DWORD processId);
		static std::wstring QueryObjectTypeNameNt(HANDLE hObject, DWORD processId);

	public:
		BackendNt() = default;
		~BackendNt() override = default;

		BOOL QueryProcessInformation(Corvus::Object::ProcessEntry& processEntry) override;
		BOOL QueryModuleInformation(Corvus::Object::ProcessEntry& processEntry) override;
		BOOL QueryThreadInformation(Corvus::Object::ProcessEntry& processEntry) override;
		BOOL QueryHandleInformation(Corvus::Object::ProcessEntry& processEntry) override;
		std::vector<Corvus::Object::ModuleEntry> QueryModules(Corvus::Object::ProcessObject& process) override;
		std::vector<Corvus::Object::ThreadEntry> QueryThreads(Corvus::Object::ProcessObject& process) override;
		std::vector<Corvus::Object::HandleEntry> QueryHandles(Corvus::Object::ProcessObject& process) override;
	};
}