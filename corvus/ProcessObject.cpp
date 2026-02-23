#include "ProcessObject.h"

namespace Corvus::Object
{
	const ProcessEntry& ProcessObject::GetProcessEntry() const noexcept { return m_processEntry; }
	const std::vector<ModuleEntry>& ProcessObject::GetModules() const noexcept { return m_modules; }
	const std::vector<ThreadEntry>& ProcessObject::GetThreads() const noexcept { return m_threads; }
	const std::vector<HandleEntry>& ProcessObject::GetHandles() const noexcept { return m_handles; }

	void ProcessObject::SetProcessEntry(const ProcessEntry& processEntry) { m_processEntry = processEntry; }
	void ProcessObject::SetModules(const std::vector<ModuleEntry>& modules) { m_modules = modules; }
	void ProcessObject::SetThreads(const std::vector<ThreadEntry>& threads) { m_threads = threads; }
	void ProcessObject::SetHandles(const std::vector<HandleEntry>& handles) { m_handles = handles; }
	void ProcessObject::AddModule(const ModuleEntry& moduleEntry) { m_modules.push_back(moduleEntry); }
	void ProcessObject::AddThread(const ThreadEntry& threadEntry) { m_threads.push_back(threadEntry); }
	void ProcessObject::AddHandle(const HandleEntry& handleEntry) { m_handles.push_back(handleEntry); }
}