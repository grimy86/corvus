#pragma once
#include "ProcessStructures.h"
#include <vector>

namespace Corvus::Object
{
	/// <summary>
	/// Process Object / Domain Model / Entity.
	/// <para> Encapsulates: process information, threads, modules and handles. </para>
	/// </summary>
	class ProcessObject final
	{
	private:
		ProcessEntry m_processEntry{};
		std::vector<ModuleEntry> m_modules{};
		std::vector<ThreadEntry> m_threads{};
		std::vector<HandleEntry> m_handles{};

	public:
		ProcessObject() = default;
		~ProcessObject() = default;

		// Non-copyable and non-movable
		ProcessObject(const ProcessObject&) = delete;
		ProcessObject(ProcessObject&&) = delete;
		ProcessObject& operator=(const ProcessObject&) = delete;
		ProcessObject& operator=(ProcessObject&&) = delete;

		const ProcessEntry& GetProcessEntry() const noexcept;
		const std::vector<ModuleEntry>& GetModules() const noexcept;
		const std::vector<ThreadEntry>& GetThreads() const noexcept;
		const std::vector<HandleEntry>& GetHandles() const noexcept;

		void SetProcessEntry(const ProcessEntry& processEntry);
		void SetModules(const std::vector<ModuleEntry>& modules);
		void SetThreads(const std::vector<ThreadEntry>& threads);
		void SetHandles(const std::vector<HandleEntry>& handles);
		void AddModule(const ModuleEntry& moduleEntry);
		void AddThread(const ThreadEntry& threadEntry);
		void AddHandle(const HandleEntry& handleEntry);
	};
}