#include "process.hpp"

#include <Psapi.h>

#pragma comment(lib, "Psapi.lib")

namespace corvus::process
{
	// =========================
	// Helpers
	// =========================

	bool IsProcessWow64(DWORD pid)
	{
		BOOL wow64 = FALSE;

		HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
		if (!hProcess)
			return false;

		if (!IsWow64Process(hProcess, &wow64))
		{
			CloseHandle(hProcess);
			return false;
		}

		CloseHandle(hProcess);
		return wow64 == TRUE;
	}

	bool HasVisibleWindow(DWORD pid)
	{
		for (HWND hwnd = GetTopWindow(nullptr); hwnd; hwnd = GetNextWindow(hwnd, GW_HWNDNEXT))
		{
			DWORD winPid = 0;
			GetWindowThreadProcessId(hwnd, &winPid);

			if (winPid == pid && IsWindowVisible(hwnd))
				return true;
		}
		return false;
	}

	// =========================
	// Process Enumeration
	// =========================

	std::vector<ProcessInfo> EnumerateProcesses(bool onlyVisible)
	{
		std::vector<ProcessInfo> result;

		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (snapshot == INVALID_HANDLE_VALUE)
			return result;

		PROCESSENTRY32W entry{};
		entry.dwSize = sizeof(entry);

		if (Process32FirstW(snapshot, &entry))
		{
			do
			{
				if (!entry.th32ProcessID)
					continue;

				if (onlyVisible && !HasVisibleWindow(entry.th32ProcessID))
					continue;

				ProcessInfo info{};
				info.pid = entry.th32ProcessID;
				info.exeName = entry.szExeFile;
				info.isWow64 = IsProcessWow64(info.pid);

				result.push_back(info);

			} while (Process32NextW(snapshot, &entry));
		}

		CloseHandle(snapshot);
		return result;
	}

	DWORD GetProcessIdByName(const std::string& processName)
	{
		DWORD pid = 0;
		std::wstring target = converter::StringToWString(processName);

		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (snapshot == INVALID_HANDLE_VALUE)
			return 0;

		PROCESSENTRY32W entry{};
		entry.dwSize = sizeof(entry);

		if (Process32FirstW(snapshot, &entry))
		{
			do
			{
				if (!_wcsicmp(entry.szExeFile, target.c_str()))
				{
					pid = entry.th32ProcessID;
					break;
				}
			} while (Process32NextW(snapshot, &entry));
		}

		CloseHandle(snapshot);
		return pid;
	}

	// =========================
	// Legacy helpers (kept)
	// =========================

	std::vector<std::string> GetVisibleProcesses()
	{
		std::vector<std::string> out;
		auto processes = EnumerateProcesses(true);

		for (const auto& p : processes)
		{
			out.push_back(
				std::to_string(p.pid) + " - " +
				converter::WStringToString(p.exeName)
			);
		}
		return out;
	}

	std::vector<std::string> GetFilteredProcesses()
	{
		return GetVisibleProcesses();
	}

	// =========================
	// Modules
	// =========================

	std::vector<ModuleInfo> EnumerateModules(DWORD pid)
	{
		std::vector<ModuleInfo> modules;

		HANDLE snapshot = CreateToolhelp32Snapshot(
			TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
			pid
		);

		if (snapshot == INVALID_HANDLE_VALUE)
			return modules;

		MODULEENTRY32W entry{};
		entry.dwSize = sizeof(entry);

		if (Module32FirstW(snapshot, &entry))
		{
			do
			{
				ModuleInfo mod{};
				mod.name = entry.szModule;
				mod.baseAddress = reinterpret_cast<uintptr_t>(entry.modBaseAddr);
				mod.size = entry.modBaseSize;

				modules.push_back(mod);

			} while (Module32NextW(snapshot, &entry));
		}

		CloseHandle(snapshot);
		return modules;
	}

	// =========================
	// Threads
	// =========================

	std::vector<ThreadInfo> EnumerateThreads(DWORD pid)
	{
		std::vector<ThreadInfo> threads;

		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (snapshot == INVALID_HANDLE_VALUE)
			return threads;

		THREADENTRY32 entry{};
		entry.dwSize = sizeof(entry);

		if (Thread32First(snapshot, &entry))
		{
			do
			{
				if (entry.th32OwnerProcessID != pid)
					continue;

				ThreadInfo info{};
				info.threadId = entry.th32ThreadID;
				info.ownerPid = pid;
				info.priority = entry.tpBasePri;

				threads.push_back(info);

			} while (Thread32Next(snapshot, &entry));
		}

		CloseHandle(snapshot);
		return threads;
	}

	bool SuspendThreadById(DWORD threadId)
	{
		HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadId);
		if (!hThread)
			return false;

		SuspendThread(hThread);
		CloseHandle(hThread);
		return true;
	}

	bool ResumeThreadById(DWORD threadId)
	{
		HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadId);
		if (!hThread)
			return false;

		ResumeThread(hThread);
		CloseHandle(hThread);
		return true;
	}

	// =========================
	// Handles (placeholder)
	// =========================

	std::vector<HandleInfo> EnumerateHandles(DWORD /*pid*/)
	{
		// NT implementation intentionally deferred.
		// Exposed API is stable; backend can change later.
		return {};
	}

	// =========================
	// Win32_Process
	// =========================

	Win32_Process::Win32_Process(const std::string& processName)
		: _processName(processName)
	{
		_processId = GetProcessIdByName(processName);
		if (!_processId)
			return;

		_processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, _processId);
		if (!_processHandle)
			return;

		_moduleBaseAddress = memory::GetModuleBaseAddress(_processId, processName);
	}

	Win32_Process::~Win32_Process()
	{
		if (_processHandle)
			CloseHandle(_processHandle);
	}

	std::vector<ModuleInfo> Win32_Process::GetModules() const
	{
		return EnumerateModules(_processId);
	}

	std::vector<ThreadInfo> Win32_Process::GetThreads() const
	{
		return EnumerateThreads(_processId);
	}

	std::vector<HandleInfo> Win32_Process::GetHandles() const
	{
		return EnumerateHandles(_processId);
	}
}