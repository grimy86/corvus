#pragma once

#include <string>
#include <vector>
#include <windows.h>
#include <TlHelp32.h>

#include "memory.hpp"
#include "converter.hpp"

namespace corvus::process
{
	// =========================
	// Process
	// =========================

	struct ProcessInfo
	{
		DWORD        pid{};
		std::wstring exeName{};
		bool         isWow64{};
	};

	bool IsProcessWow64(DWORD pid);
	bool HasVisibleWindow(DWORD pid);

	std::vector<ProcessInfo> EnumerateProcesses(bool onlyVisible = true);
	DWORD GetProcessIdByName(const std::string& processName);

	// Legacy helpers (can be deprecated later)
	std::vector<std::string> GetVisibleProcesses();
	std::vector<std::string> GetFilteredProcesses();

	// =========================
	// Modules
	// =========================

	struct ModuleInfo
	{
		std::wstring name{};
		uintptr_t    baseAddress{};
		DWORD        size{};
	};

	std::vector<ModuleInfo> EnumerateModules(DWORD pid);

	// =========================
	// Threads
	// =========================

	struct ThreadInfo
	{
		DWORD threadId{};
		DWORD ownerPid{};
		int   priority{};
	};

	std::vector<ThreadInfo> EnumerateThreads(DWORD pid);

	bool SuspendThreadById(DWORD threadId);
	bool ResumeThreadById(DWORD threadId);

	// =========================
	// Handles (advanced / NT)
	// =========================

	enum class HandleType
	{
		Unknown,
		Process,
		Thread,
		File,
		Section,
		Mutex,
		Event
	};

	struct HandleInfo
	{
		HANDLE     handle{};
		DWORD      ownerPid{};
		HandleType type{ HandleType::Unknown };
		ACCESS_MASK access{};
	};

	// NOTE:
	// This will require NtQuerySystemInformation internally.
	// Exposed cleanly here so GUI / SDK users don't touch NT directly.
	std::vector<HandleInfo> EnumerateHandles(DWORD pid);

	// =========================
	// Win32_Process abstraction
	// =========================

	class Win32_Process
	{
	private:
		std::string _processName{};
		DWORD       _processId{};
		uintptr_t   _moduleBaseAddress{};
		HANDLE      _processHandle{};

	public:
		// Getters
		inline const std::string& GetProcessName() const { return _processName; }
		inline DWORD GetProcessId() const { return _processId; }
		inline uintptr_t GetModuleBase() const { return _moduleBaseAddress; }
		inline HANDLE GetProcessHandle() const { return _processHandle; }

		// High-level helpers
		std::vector<ModuleInfo>  GetModules() const;
		std::vector<ThreadInfo>  GetThreads() const;
		std::vector<HandleInfo>  GetHandles() const;

		// Lifecycle
		explicit Win32_Process(const std::string& processName);
		Win32_Process(const Win32_Process&) = delete;
		Win32_Process& operator=(const Win32_Process&) = delete;
		~Win32_Process();
	};
}