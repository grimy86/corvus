#include "process.hpp"
#include <TlHelp32.h>
#include <Psapi.h>
#include <ProcessSnapshot.h>

namespace corvus::process
{
	void WIN32Process::QueryNameW32()
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

	void WIN32Process::QueryModulesW32()
	{
		HANDLE hSnapshot{ CreateToolhelp32Snapshot(
			TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
			m_processId
		) };

		HANDLE hProcess{ OpenProcessHandleW32(
			m_processId,
			PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
		) };

		if (hSnapshot == INVALID_HANDLE_VALUE || hProcess == INVALID_HANDLE_VALUE)
			return;

		MODULEINFO moduleInfoBuffer{};
		MODULEENTRY32W entry{};
		entry.dwSize = sizeof(entry);

		if (Module32FirstW(hSnapshot, &entry))
		{
			do
			{
				K32GetModuleInformation(hProcess, reinterpret_cast<HMODULE>(entry.modBaseAddr),
					&moduleInfoBuffer, sizeof(moduleInfoBuffer));

				ModuleEntry module{};
				module.moduleName = entry.szModule;
				module.modulePath = entry.szExePath;
				module.size = entry.dwSize;
				module.baseAddress = reinterpret_cast<uintptr_t>(entry.modBaseAddr);
				module.moduleBaseSize = entry.modBaseSize;
				module.ownerHandle = entry.hModule;
				module.entryPoint = moduleInfoBuffer.EntryPoint;
				module.moduleId = entry.th32ModuleID;
				module.processId = entry.th32ProcessID;
				module.globalLoadCount = entry.GlblcntUsage;
				module.processLoadCount = entry.ProccntUsage;

				m_modules.push_back(module);
			} while (Module32NextW(hSnapshot, &entry));
		}

		CloseHandle(hSnapshot);
	}

	void WIN32Process::QueryThreadsW32()
	{
		std::vector<ThreadEntry> threads;

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

				ThreadEntry thread{};
				thread.size = entry.dwSize;
				thread.cntUsage = entry.cntUsage;
				thread.threadId = entry.th32ThreadID;
				thread.ownerProcessId = entry.th32OwnerProcessID;
				thread.basePriority = entry.tpBasePri;
				thread.deltaPriority = entry.tpDeltaPri;
				thread.flags = entry.dwFlags;
				m_threads.push_back(thread);

			} while (Thread32Next(snapshot, &entry));
		}

		CloseHandle(snapshot);
	}

	void WIN32Process::QueryHandlesW32()
	{
		HANDLE pHandle = OpenProcessHandleW32(m_processId, PROCESS_QUERY_INFORMATION);
		if (!IsValidHandle(pHandle))
			return;

		const PSS_CAPTURE_FLAGS captureFlags =
			PSS_CAPTURE_HANDLES |
			PSS_CAPTURE_HANDLE_NAME_INFORMATION |
			PSS_CAPTURE_HANDLE_BASIC_INFORMATION |
			PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION |
			PSS_CAPTURE_HANDLE_TRACE;

		HPSS hSnapshot{};
		DWORD captureStatus{ PssCaptureSnapshot(pHandle, captureFlags, 0, &hSnapshot) };
		if (captureStatus != ERROR_SUCCESS)
		{
			CloseHandle(pHandle);
			return;
		}

		HPSSWALK hWalkMarker{};
		if (PssWalkMarkerCreate(nullptr, &hWalkMarker) != ERROR_SUCCESS)
		{
			PssFreeSnapshot(GetCurrentProcess(), hSnapshot);
			CloseHandle(pHandle);
			return;
		}

		// m_handles.clear();
		// m_handles.reserve(1024);

		for (;;)
		{
			PSS_HANDLE_ENTRY handleBuffer{};
			DWORD status = PssWalkSnapshot(
				hSnapshot,
				PSS_WALK_HANDLES,
				hWalkMarker,
				&handleBuffer,
				sizeof(handleBuffer)
			);

			if (status == ERROR_NO_MORE_ITEMS)
				break;

			if (status != ERROR_SUCCESS)
				break;

			HandleEntry handle{};

			// Safe string copy using provided lengths (bytes → wchar count)
			if (handleBuffer.TypeName && handleBuffer.TypeNameLength)
			{
				handle.TypeName.assign(
					handleBuffer.TypeName,
					handleBuffer.TypeNameLength / sizeof(wchar_t)
				);
			}

			if (handleBuffer.ObjectName && handleBuffer.ObjectNameLength)
			{
				handle.ObjectName.assign(
					handleBuffer.ObjectName,
					handleBuffer.ObjectNameLength / sizeof(wchar_t)
				);
			}

			handle.handle = handleBuffer.Handle;
			handle.flags = handleBuffer.Flags;
			handle.objectType = static_cast<HandleType>(handleBuffer.ObjectType);
			handle.Attributes = handleBuffer.Attributes;
			handle.GrantedAccess = handleBuffer.GrantedAccess;
			handle.HandleCount = handleBuffer.HandleCount;
			handle.PointerCount = handleBuffer.PointerCount;
			handle.PagedPoolCharge = handleBuffer.PagedPoolCharge;
			handle.NonPagedPoolCharge = handleBuffer.NonPagedPoolCharge;
			handle.TypeNameLength = handleBuffer.TypeNameLength;
			handle.ObjectNameLength = handleBuffer.ObjectNameLength;

			m_handles.push_back(handle);
		}

		PssWalkMarkerFree(hWalkMarker);
		PssFreeSnapshot(GetCurrentProcess(), hSnapshot);
		CloseHandle(pHandle);
	}

	void WIN32Process::QueryModuleBaseAddressW32()
	{
		if (m_name.empty()) return;
		m_moduleBaseAddress = GetModuleBaseAddressW32(m_processId, m_name);
	}

	void WIN32Process::QueryPEBAddressW32()
	{
		uintptr_t pebAddress{ 0x0 };
		m_pebAddress = pebAddress;
	}

	void WIN32Process::QueryArchitectureTypeW32()
	{
		HANDLE hProcess =
			OpenProcessHandleW32(m_processId, PROCESS_QUERY_LIMITED_INFORMATION);

		if (!IsValidHandle(hProcess))
		{
			m_architectureType = ArchitectureType::Unknown;
			return;
		}

		USHORT processMachine{ IMAGE_FILE_MACHINE_UNKNOWN };
		USHORT nativeMachine{ IMAGE_FILE_MACHINE_UNKNOWN };

		if (!IsWow64Process2(hProcess, &processMachine, &nativeMachine))
		{
			CloseHandle(hProcess);
			m_architectureType = ArchitectureType::Unknown;
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
			m_architectureType = ArchitectureType::Unknown;
			break;

		case IMAGE_FILE_MACHINE_I386:
			m_architectureType = ArchitectureType::x86;
			break;

		case IMAGE_FILE_MACHINE_AMD64:
			m_architectureType = ArchitectureType::x64;
			break;

		case IMAGE_FILE_MACHINE_ARM:
			m_architectureType = ArchitectureType::arm;
			break;

		case IMAGE_FILE_MACHINE_ARM64:
			m_architectureType = ArchitectureType::arm64;
			break;

		default:
			m_architectureType = ArchitectureType::Unknown;
			break;
		}
	}

	void WIN32Process::QueryWow64W32()
	{
		HANDLE hProcess{ OpenProcessHandleW32(m_processId, PROCESS_QUERY_LIMITED_INFORMATION) };

		if (IsValidHandle(hProcess))
		{
			IsWow64Process(hProcess, &m_isWow64);
			CloseHandle(hProcess);
		}
	}

	void WIN32Process::QueryVisibleWindowW32()
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

	std::vector<WIN32Process> WIN32Process::GetProcessListW32()
	{
		std::vector<WIN32Process> result;

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
				WIN32Process proc{ entry.th32ProcessID };
				result.push_back(proc);

			} while (Process32NextW(snapshot, &entry));
		}

		CloseHandle(snapshot);
		return result;
	}

	HANDLE WIN32Process::OpenProcessHandleW32(const DWORD processId, const ACCESS_MASK accessMask)
	{
		return OpenProcess(accessMask, FALSE, processId);
	}

	uintptr_t WIN32Process::GetModuleBaseAddressW32(const DWORD& processId, const std::wstring& moduleName)
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

	void WIN32Process::PatchExecutionEW32(HANDLE processHandle, DWORD destination, BYTE* value, unsigned int size)
	{
		// Changes the protection on a region of committed pages in the virtual address space of a specified process.
		// https://learn.microsoft.com/en-us/windows/win32/Memory/memory-protection-constants

		DWORD oldPageProtection;
		VirtualProtectEx(processHandle, (void*)destination, size, PAGE_EXECUTE_READWRITE, &oldPageProtection);
		WriteProcessMemory(processHandle, (void*)destination, value, size, nullptr);
	}

	void WIN32Process::NopExecutionEW32(HANDLE processHandle, DWORD destination, unsigned int size)
	{
		// Filling an array with x86 NOP instructions (0x90)
		BYTE* noOperationArray = new BYTE[size];
		memset(noOperationArray, 0x90, size);

		PatchExecutionEW32(processHandle, destination, noOperationArray, size);
		delete[] noOperationArray;
	}

	// Find multi-level pointers (external)
	DWORD WIN32Process::FindDMAAddyEW32(HANDLE processHandle, DWORD ptr, std::vector<DWORD> offsets)
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
	DWORD WIN32Process::FindDMAAddyIW32(DWORD ptr, std::vector<DWORD> offsets)
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
	void WIN32Process::PatchExecutionIW32(DWORD destination, BYTE* value, unsigned int size)
	{
		DWORD oldPageProtection;
		VirtualProtect((void*)destination, size, PAGE_EXECUTE_READWRITE, &oldPageProtection);
		memcpy((void*)destination, value, size);
		VirtualProtect((void*)destination, size, oldPageProtection, &oldPageProtection);
	}

	//Internal nop function, uses memset instead of WPM
	void  WIN32Process::NopExecutionIW32(DWORD destination, unsigned int size)
	{
		DWORD oldPageProtection;
		VirtualProtect((void*)destination, size, PAGE_EXECUTE_READWRITE, &oldPageProtection);
		memset((void*)destination, 0x90, size);
		VirtualProtect((void*)destination, size, oldPageProtection, &oldPageProtection);
	}

	BOOL  WIN32Process::SuspendThreadW32(const DWORD threadId)
	{
		HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadId);
		if (!hThread)
			return FALSE;

		SuspendThread(hThread);
		CloseHandle(hThread);
		return TRUE;
	}

	BOOL WIN32Process::ResumeThreadW32(const DWORD threadId)
	{
		HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadId);
		if (!hThread)
			return FALSE;

		ResumeThread(hThread);
		CloseHandle(hThread);
		return TRUE;
	}

	WIN32Process::WIN32Process(const DWORD processId)
		: WindowsProcessBase(processId)
	{
		QueryNameW32();
		QueryModulesW32();
		QueryThreadsW32();
		QueryHandlesW32();
		QueryPEBAddressW32();
		QueryArchitectureTypeW32();
		QueryWow64W32();
		QueryVisibleWindowW32();
	}
}