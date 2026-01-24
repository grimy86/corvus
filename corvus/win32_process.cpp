#include "win32_process.hpp"
#include "converter.hpp"
#include <TlHelp32.h>

namespace corvus::process
{
	void WindowsProcess::QueryName()
	{
		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (snapshot == INVALID_HANDLE_VALUE)
			return;

		PROCESSENTRY32W entry{};
		entry.dwSize = sizeof(entry);

		if (Process32FirstW(snapshot, &entry))
		{
			do
			{
				if (entry.th32ProcessID == m_processId)
				{
					m_name = entry.szExeFile;
					break;
				}
			} while (Process32NextW(snapshot, &entry));
		}

		CloseHandle(snapshot);
	}

	void WindowsProcess::QueryModules()
	{
		HANDLE snapshot = CreateToolhelp32Snapshot(
			TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
			m_processId
		);

		if (snapshot == INVALID_HANDLE_VALUE) return;

		MODULEENTRY32W entry{};
		entry.dwSize = sizeof(entry);

		if (Module32FirstW(snapshot, &entry))
		{
			do
			{
				WindowsModule module{};
				module.description = entry.szModule;
				module.baseAddress = reinterpret_cast<uintptr_t>(entry.modBaseAddr);
				module.size = entry.modBaseSize;
				m_modules.push_back(module);

			} while (Module32NextW(snapshot, &entry));
		}

		CloseHandle(snapshot);
	}

	void WindowsProcess::QueryThreads()
	{
		std::vector<ProcessThread> threads;

		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (snapshot == INVALID_HANDLE_VALUE) return;

		THREADENTRY32 entry{};
		entry.dwSize = sizeof(entry);

		if (Thread32First(snapshot, &entry))
		{
			do
			{
				if (entry.th32OwnerProcessID != m_processId)
					continue;

				ProcessThread thread{};
				thread.threadId = entry.th32ThreadID;
				thread.ownerPid = entry.th32OwnerProcessID;
				thread.priority = entry.tpBasePri;
				m_threads.push_back(thread);

			} while (Thread32Next(snapshot, &entry));
		}

		CloseHandle(snapshot);
	}

	void WindowsProcess::QueryHandles()
	{
		return;
	}

	void WindowsProcess::QueryModuleBaseAddress()
	{
		if (m_name.empty()) return;
		m_moduleBaseAddress = GetModuleBaseAddress(m_processId, m_name);
	}

	void WindowsProcess::QueryPEBAddress()
	{

	}

	void WindowsProcess::QueryArchitecture()
	{
		HANDLE hProcess =
			OpenProcessHandle(m_processId, PROCESS_QUERY_LIMITED_INFORMATION);

		if (!IsValidHandle(hProcess))
		{
			m_architecture = Architecture::Unknown;
			return;
		}

		USHORT processMachine{ IMAGE_FILE_MACHINE_UNKNOWN };
		USHORT nativeMachine{ IMAGE_FILE_MACHINE_UNKNOWN };

		if (!IsWow64Process2(hProcess, &processMachine, &nativeMachine))
		{
			CloseHandle(hProcess);
			m_architecture = Architecture::Unknown;
			return;
		}

		CloseHandle(hProcess);

		// If the process is emulated, use the emulated architecture.
		// Otherwise, use the native OS architecture.
		const USHORT machine{
			(processMachine != IMAGE_FILE_MACHINE_UNKNOWN)
			? processMachine
			: nativeMachine };

		switch (machine)
		{
		case IMAGE_FILE_MACHINE_UNKNOWN:
			m_architecture = Architecture::Unknown;
			break;

		case IMAGE_FILE_MACHINE_I386:
			m_architecture = Architecture::x86;
			break;

		case IMAGE_FILE_MACHINE_AMD64:
			m_architecture = Architecture::x64;
			break;

		case IMAGE_FILE_MACHINE_ARM:
			m_architecture = Architecture::arm;
			break;

		case IMAGE_FILE_MACHINE_ARM64:
			m_architecture = Architecture::arm64;
			break;

		default:
			m_architecture = Architecture::Unknown;
			break;
		}
	}

	void WindowsProcess::QueryWow64()
	{
		HANDLE hProcess{ OpenProcessHandle(m_processId, PROCESS_QUERY_LIMITED_INFORMATION) };

		if (IsValidHandle(hProcess))
		{
			IsWow64Process(hProcess, &m_isWow64);
			CloseHandle(hProcess);
		}
	}

	void WindowsProcess::QueryVisibleWindow()
	{
		m_hasVisibleWindow = FALSE;

		for (HWND hwnd = GetTopWindow(nullptr); hwnd; hwnd = GetNextWindow(hwnd, GW_HWNDNEXT))
		{
			DWORD pid = 0;
			GetWindowThreadProcessId(hwnd, &pid);

			if (pid == m_processId && IsWindowVisible(hwnd))
			{
				m_hasVisibleWindow = TRUE;
				return;
			}
		}
	}

	std::vector<WindowsProcess> WindowsProcess::GetProcessList()
	{
		std::vector<WindowsProcess> result;

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
				WindowsProcess proc{ entry.th32ProcessID };
				result.push_back(proc);

			} while (Process32NextW(snapshot, &entry));
		}

		CloseHandle(snapshot);
		return result;
	}

	HANDLE WindowsProcess::OpenProcessHandle(const DWORD processId, const ACCESS_MASK accessMask)
	{
		return OpenProcess(accessMask, FALSE, processId);
	}

	uintptr_t WindowsProcess::GetModuleBaseAddress(const DWORD& processId, const std::wstring& moduleName)
	{
		// Take a snapshot of 32 & 64-bit modules
		HANDLE hSnapShotHandle{ CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId) };
		uintptr_t moduleBaseAddress{};

		if (!IsValidHandle(hSnapShotHandle))
		{
			return moduleBaseAddress;
		}

		MODULEENTRY32 modEntry{};
		modEntry.dwSize = sizeof(MODULEENTRY32);
		if (!Module32First(hSnapShotHandle, &modEntry))
		{
			CloseHandle(hSnapShotHandle);
			return moduleBaseAddress;
		}

		do
		{
			if (!_wcsicmp(modEntry.szModule, moduleName.c_str()))
			{
				CloseHandle(hSnapShotHandle);
				return reinterpret_cast<uintptr_t>(modEntry.modBaseAddr);
			}
		} while (Module32Next(hSnapShotHandle, &modEntry));

		CloseHandle(hSnapShotHandle);
		return moduleBaseAddress;
	}

	void WindowsProcess::PatchExecution(HANDLE processHandle, DWORD destination, BYTE* value, unsigned int size)
	{
		// Changes the protection on a region of committed pages in the virtual address space of a specified process.
		// https://learn.microsoft.com/en-us/windows/win32/Memory/memory-protection-constants

		DWORD oldPageProtection;
		VirtualProtectEx(processHandle, (void*)destination, size, PAGE_EXECUTE_READWRITE, &oldPageProtection);
		WriteProcessMemory(processHandle, (void*)destination, value, size, nullptr);
	}

	void WindowsProcess::NopExecution(HANDLE processHandle, DWORD destination, unsigned int size)
	{
		// Filling an array with x86 NOP instructions (0x90)
		BYTE* noOperationArray = new BYTE[size];
		memset(noOperationArray, 0x90, size);

		PatchExecution(processHandle, destination, noOperationArray, size);
		delete[] noOperationArray;
	}

	// Find multi-level pointers (external)
	DWORD WindowsProcess::FindDMAAddy(HANDLE processHandle, DWORD ptr, std::vector<DWORD> offsets)
	{
		DWORD addr{ ptr };
		for (unsigned int i = 0; i < offsets.size(); ++i)
		{
			ReadProcessMemory(processHandle, (void*)addr, &addr, sizeof(addr), nullptr);
			addr += offsets[i];
		}
		return addr;
	}

	// Internal Find multi-level pointers
	DWORD WindowsProcess::FindDMAAddyI(DWORD ptr, std::vector<DWORD> offsets)
	{
		DWORD addr{ ptr };
		for (unsigned int i = 0; i < offsets.size(); ++i)
		{
			addr = *(DWORD*)addr;
			addr += offsets[i];
		}
		return addr;
	}

	//Internal patch function, uses VirtualProtect instead of VirtualProtectEx
	void WindowsProcess::PatchExecutionI(DWORD destination, BYTE* value, unsigned int size)
	{
		DWORD oldPageProtection;
		VirtualProtect((void*)destination, size, PAGE_EXECUTE_READWRITE, &oldPageProtection);
		memcpy((void*)destination, value, size);
		VirtualProtect((void*)destination, size, oldPageProtection, &oldPageProtection);
	}

	//Internal nop function, uses memset instead of WPM
	void  WindowsProcess::NopExecutionI(DWORD destination, unsigned int size)
	{
		DWORD oldPageProtection;
		VirtualProtect((void*)destination, size, PAGE_EXECUTE_READWRITE, &oldPageProtection);
		memset((void*)destination, 0x90, size);
		VirtualProtect((void*)destination, size, oldPageProtection, &oldPageProtection);
	}

	bool  WindowsProcess::SuspendThreadById(const DWORD threadId)
	{
		HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadId);
		if (!hThread)
			return false;

		SuspendThread(hThread);
		CloseHandle(hThread);
		return true;
	}

	bool WindowsProcess::ResumeThreadById(const DWORD threadId)
	{
		HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadId);
		if (!hThread)
			return false;

		ResumeThread(hThread);
		CloseHandle(hThread);
		return true;
	}

	WindowsProcess::WindowsProcess(const DWORD processId)
		: m_processId(processId)
	{
		QueryName();
		QueryModules();
		QueryThreads();
		QueryHandles();
		QueryPEBAddress();
		QueryArchitecture();
		QueryWow64();
		QueryVisibleWindow();
	}
}