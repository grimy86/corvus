#include "WindowsProvider32.h"
#include "MemoryService.h"
#include <TlHelp32.h>
#include <Psapi.h>

namespace Corvus::Data
{
#pragma region WRITE
	BOOL EnableSeDebugPrivilege32()
	{
		BOOL bRet{ FALSE };
		HANDLE hToken{ nullptr };
		LUID luid{};

		if (OpenProcessToken(
			GetCurrentProcess(),
			TOKEN_ADJUST_PRIVILEGES,
			&hToken))
		{
			if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
			{
				TOKEN_PRIVILEGES tPriv{};
				tPriv.PrivilegeCount = 1;
				tPriv.Privileges[0].Luid = luid;
				tPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

				bRet = AdjustTokenPrivileges(hToken,
					FALSE,
					&tPriv,
					sizeof(TOKEN_PRIVILEGES),
					nullptr,
					nullptr);
			}
		}

		return bRet;
	}

	BOOL EnableSeDebugPrivilege32(const DWORD processId)
	{
		HANDLE hProc{ OpenProcessHandle(processId, PROCESS_ALL_ACCESS) };
		if (!IsValidHandle(hProc)) return FALSE;

		BOOL bRet{ FALSE };
		HANDLE hToken{ nullptr };
		LUID luid{};

		if (OpenProcessToken(
			hProc,
			TOKEN_ADJUST_PRIVILEGES,
			&hToken))
		{
			if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
			{
				TOKEN_PRIVILEGES tPriv{};
				tPriv.PrivilegeCount = 1;
				tPriv.Privileges[0].Luid = luid;
				tPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

				bRet = AdjustTokenPrivileges(hToken,
					FALSE,
					&tPriv,
					sizeof(TOKEN_PRIVILEGES),
					nullptr,
					nullptr);
			}
		}

		CloseProcessHandle(hProc);
		return bRet;
	}

	BOOL SetThreadPriority32(int priorityMask)
	{
		return SetPriorityClass(GetCurrentProcess(), priorityMask);
	}

	BOOL  SuspendThread32(const DWORD threadId)
	{
		HANDLE hThread{ OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadId) };
		if (!hThread) return FALSE;
		SuspendThread(hThread);
		CloseProcessHandle(hThread);
		return TRUE;
	}

	BOOL ResumeThread32(const DWORD threadId)
	{
		HANDLE hThread{ OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadId) };
		if (!hThread) return FALSE;
		ResumeThread(hThread);
		CloseProcessHandle(hThread);
		return TRUE;
	}

	void PatchExecutionExt32(HANDLE processHandle, DWORD destination, BYTE* value, unsigned int size)
	{
		// Changes the protection on a region of committed pages in the virtual address space of a specified process.
		// https://learn.microsoft.com/en-us/windows/win32/Service/memory-protection-constants

		DWORD oldPageProtection;
		VirtualProtectEx(processHandle, (void*)destination, size, PAGE_EXECUTE_READWRITE, &oldPageProtection);
		WriteProcessMemory(processHandle, (void*)destination, value, size, nullptr);
	}

	void PatchExecutionInt32(DWORD destination, BYTE* value, unsigned int size)
	{
		DWORD oldPageProtection;
		VirtualProtect((void*)destination, size, PAGE_EXECUTE_READWRITE, &oldPageProtection);
		memcpy((void*)destination, value, size);
		VirtualProtect((void*)destination, size, oldPageProtection, &oldPageProtection);
	}

	void NopExecutionExt32(HANDLE processHandle, DWORD destination, unsigned int size)
	{
		// Filling an array with x86 NOP instructions (0x90)
		BYTE* noOperationArray = new BYTE[size];
		memset(noOperationArray, 0x90, size);

		PatchExecutionExt32(processHandle, destination, noOperationArray, size);
		delete[] noOperationArray;
	}

	void NopExecutionInt32(DWORD destination, unsigned int size)
	{
		DWORD oldPageProtection;
		VirtualProtect((void*)destination, size, PAGE_EXECUTE_READWRITE, &oldPageProtection);
		memset((void*)destination, 0x90, size);
		VirtualProtect((void*)destination, size, oldPageProtection, &oldPageProtection);
	}

	DWORD FindDMAAddyExt32(HANDLE processHandle, DWORD ptr, std::vector<DWORD> offsets)
	{
		DWORD addr{ ptr };
		for (unsigned int i = 0; i < offsets.size(); ++i)
		{
			ReadProcessMemory(processHandle, (void*)addr, &addr, sizeof(addr), nullptr);
			addr += offsets[i];
		}
		return addr;
	}

	DWORD FindDMAAddyInt32(DWORD ptr, std::vector<DWORD> offsets)
	{
		DWORD addr{ ptr };
		for (unsigned int i = 0; i < offsets.size(); ++i)
		{
			addr = *(DWORD*)addr;
			addr += offsets[i];
		}
		return addr;
	}
#pragma endregion

#pragma region READ
	Corvus::Object::ProcessEntry QueryProcessInfo(HANDLE hProcess, DWORD processId)
	{
		if (!Corvus::Service::IsValidHandle(hProcess)) return {};

		HANDLE hProcessSnapshot{ CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
		if (!Corvus::Service::IsValidHandle(hProcessSnapshot)) return {};

		PROCESSENTRY32W pEntry32W{};
		pEntry32W.dwSize = sizeof(PROCESSENTRY32W);
		if (!Process32FirstW(hProcessSnapshot, &pEntry32W))
		{
			Corvus::Service::CloseHandle32(hProcessSnapshot);
			return {};
		}

		Corvus::Object::ProcessEntry pEntry{};
		do
		{
			if (pEntry32W.th32ProcessID == processId)
			{
				pEntry.processName = pEntry32W.szExeFile;
				pEntry.imageFilePath = QueryImageFilePath(hProcess);
				pEntry.parentProcessId = pEntry32W.th32ParentProcessID;
				pEntry.moduleBaseAddress = QueryModuleBaseAddress(pEntry32W.th32ProcessID, pEntry32W.szExeFile);
				pEntry.userProcessBasePriorityClass = QueryPriorityClass(hProcess);
				pEntry.hasVisibleWindow = QueryVisibleWindow(pEntry32W.th32ProcessID);
				BOOL isWow64{ FALSE };
				pEntry.architectureType = QueryArchitecture(hProcess, isWow64);
				pEntry.isWow64 = isWow64;

				break;
			}
		} while (Process32NextW(hProcessSnapshot, &pEntry32W));

		Corvus::Service::CloseHandle32(hProcessSnapshot);
		return pEntry;
	}

	std::vector<Corvus::Object::ModuleEntry> QueryModules(const Corvus::Object::ProcessObject& Object)
	{
		HANDLE hProcess{ Object.GetProcessHandle() };
		DWORD processId{ Object.GetProcessId() };

		if (!Corvus::Service::IsValidHandle(hProcess)) return {};
		HANDLE hModuleSnapshot{
			CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId) };
		if (!Corvus::Service::IsValidHandle(hModuleSnapshot)) return {};

		MODULEINFO mInfoBuffer{};
		MODULEENTRY32W mEntry{};
		mEntry.dwSize = sizeof(MODULEENTRY32W);
		if (!Module32FirstW(hModuleSnapshot, &mEntry))
		{
			Corvus::Service::CloseHandle32(hModuleSnapshot);
			return {};
		}

		std::vector<Corvus::Object::ModuleEntry> modules{};
		do
		{
			if (!K32GetModuleInformation(
				hProcess,
				reinterpret_cast<HMODULE>(mEntry.modBaseAddr),
				&mInfoBuffer,
				sizeof(mInfoBuffer)))
				continue;

			Corvus::Object::ModuleEntry module{};
			module.moduleName = mEntry.szModule;
			module.modulePath = mEntry.szExePath;
			module.structureSize = mEntry.dwSize;
			module.baseAddress = reinterpret_cast<uintptr_t>(mEntry.modBaseAddr);
			module.moduleBaseSize = mEntry.modBaseSize;
			module.entryPoint = mInfoBuffer.EntryPoint;
			module.processId = mEntry.th32ProcessID;
			module.globalLoadCount = mEntry.GlblcntUsage;
			module.processLoadCount = mEntry.ProccntUsage;
			modules.push_back(module);

		} while (Module32NextW(hModuleSnapshot, &mEntry));
		Corvus::Service::CloseHandle32(hModuleSnapshot);
		return modules;
	}

	std::vector<Corvus::Object::ThreadEntry> QueryThreads(const Corvus::Object::ProcessObject& Object)
	{
		HANDLE hProcess{ Object.GetProcessHandle() };
		DWORD processId{ Object.GetProcessId() };
		if (!Corvus::Service::IsValidHandle(hProcess)) return {};

		HANDLE hThreadSnapshot{
			CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, processId) };
		if (!Corvus::Service::IsValidHandle(hThreadSnapshot)) return {};

		THREADENTRY32 tEntry{};
		tEntry.dwSize = sizeof(THREADENTRY32);
		if (!Thread32First(hThreadSnapshot, &tEntry))
		{
			Corvus::Service::CloseHandle32(hThreadSnapshot);
			return {};
		}

		std::vector<Corvus::Object::ThreadEntry> threads{};
		do
		{
			if (tEntry.th32OwnerProcessID != processId) continue;

			Corvus::Object::ThreadEntry thread{};
			thread.structureSize = tEntry.dwSize;
			thread.threadId = tEntry.th32ThreadID;
			thread.ownerProcessId = tEntry.th32OwnerProcessID;
			thread.basePriority = tEntry.tpBasePri; //KeQueryPriorityThread
			threads.push_back(thread);

		} while (Thread32Next(hThreadSnapshot, &tEntry));
		Corvus::Service::CloseHandle32(hThreadSnapshot);
		return threads;
	}

	std::vector<Corvus::Object::HandleEntry> QueryHandles(const Corvus::Object::ProcessObject& Object)
	{
		HANDLE hProcess{ Object.GetProcessHandle() };
		if (!Corvus::Service::IsValidHandle(hProcess)) return {};
		HPSS pssSnapshot{};
		HPSSWALK hWalkMarker{};
		PSS_CAPTURE_FLAGS captureFlags{
			PSS_CAPTURE_HANDLES |
			PSS_CAPTURE_HANDLE_NAME_INFORMATION |
			PSS_CAPTURE_HANDLE_BASIC_INFORMATION |
			PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION |
			PSS_CAPTURE_HANDLE_TRACE };

		if (PssCaptureSnapshot(
			hProcess,
			captureFlags,
			0,
			&pssSnapshot) != ERROR_SUCCESS)
		{
			return {};
		}
		if (PssWalkMarkerCreate(nullptr, &hWalkMarker) != ERROR_SUCCESS)
		{
			PssFreeSnapshot(GetCurrentProcess(), pssSnapshot);
			return {};
		}

		// Pre-allocate memory
		std::vector<Corvus::Object::HandleEntry> handles(1000);
		while (true)
		{
			PSS_HANDLE_ENTRY handleBuffer{};
			const DWORD walkStatus{ PssWalkSnapshot(
				pssSnapshot,
				PSS_WALK_HANDLES,
				hWalkMarker,
				&handleBuffer,
				sizeof(handleBuffer)) };
			if (walkStatus == ERROR_NO_MORE_ITEMS) break;
			if (walkStatus != ERROR_SUCCESS) break;

			Corvus::Object::HandleEntry handle{};
			handle.typeName = handleBuffer.TypeName ? handleBuffer.TypeName : L"";
			handle.objectName = handleBuffer.ObjectName ? handleBuffer.ObjectName : L"";
			handle.handle = handleBuffer.Handle;
			handle.flags = handleBuffer.Flags;
			handle.attributes = handleBuffer.Attributes;
			handle.grantedAccess = handleBuffer.GrantedAccess;
			handle.handleCount = handleBuffer.HandleCount;
			handle.pssObjectType = handleBuffer.ObjectType;

			switch (handle.pssObjectType)
			{
			case PSS_OBJECT_TYPE_PROCESS:
				handle.targetProcessId = handleBuffer.TypeSpecificInformation.Object.ProcessId;
				break;
			case PSS_OBJECT_TYPE_THREAD:
				handle.targetProcessId = handleBuffer.TypeSpecificInformation.Thread.ProcessId;
				break;
			case PSS_OBJECT_TYPE_MUTANT:
				handle.targetProcessId = handleBuffer.TypeSpecificInformation.Mutant.OwnerProcessId;
				break;
			default:
				handle.targetProcessId = 0; // Other cases don't have a OwnerProcessId
				break;
			}

			handles.push_back(handle);
		}

		PssWalkMarkerFree(hWalkMarker);
		PssFreeSnapshot(GetCurrentProcess(), pssSnapshot);
		return handles;
	}

	std::wstring QueryImageFilePath(HANDLE hProcess)
	{
		std::wstring iFilePathBuffer{};
		iFilePathBuffer.resize(32768);
		DWORD size = static_cast<DWORD>(iFilePathBuffer.size());

		if (!QueryFullProcessImageNameW(hProcess, 0, iFilePathBuffer.data(), &size)) return L"";
		iFilePathBuffer.resize(size);

		return iFilePathBuffer;
	}

	uintptr_t QueryModuleBaseAddress(const DWORD processId, const std::wstring& processName)
	{
		MODULEENTRY32W mEntry{};
		mEntry.dwSize = sizeof(MODULEENTRY32W);
		HANDLE hModuleSnapshot{
			CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId) };

		if (!Corvus::Service::IsValidHandle(hModuleSnapshot)) return 0;
		if (!Module32FirstW(hModuleSnapshot, &mEntry))
		{
			Corvus::Service::CloseHandle32(hModuleSnapshot);
			return 0;
		}

		do
		{
			if (_wcsicmp(mEntry.szModule, processName.c_str()) == 0)
			{
				Corvus::Service::CloseHandle32(hModuleSnapshot);
				return reinterpret_cast<uintptr_t>(mEntry.modBaseAddr);
			}
		} while (Module32Next(hModuleSnapshot, &mEntry));

		Corvus::Service::CloseHandle32(hModuleSnapshot);
		return 0;
	}

	bool QueryVisibleWindow(const DWORD processId)
	{
		for (HWND hwnd = GetTopWindow(nullptr); hwnd; hwnd = GetNextWindow(hwnd, GW_HWNDNEXT))
		{
			DWORD windowThreadProcessId{};
			GetWindowThreadProcessId(hwnd, &windowThreadProcessId);
			if (windowThreadProcessId == processId && IsWindowVisible(hwnd)) return true;
		}
		return false;
	}

	Corvus::Object::ArchitectureType QueryArchitecture(HANDLE hProcess, BOOL& isWow64)
	{
		if (!Corvus::Service::IsValidHandle(hProcess)) return {};

		// processMachine = type of WoW process, nativeMachine = native architecture of host system
		USHORT processMachine{ IMAGE_FILE_MACHINE_UNKNOWN };
		USHORT nativeMachine{ IMAGE_FILE_MACHINE_UNKNOWN };
		if (!IsWow64Process2(hProcess, &processMachine, &nativeMachine))
		{
			isWow64 = FALSE;
			return Corvus::Object::ArchitectureType::Unknown;
		}

		// emulation check
		isWow64 = (processMachine != IMAGE_FILE_MACHINE_UNKNOWN);

		// determine effective architecture
		const USHORT machine{ isWow64 ? processMachine : nativeMachine };
		switch (machine)
		{
		case IMAGE_FILE_MACHINE_UNKNOWN: return Corvus::Object::ArchitectureType::Unknown;
		case IMAGE_FILE_MACHINE_I386: return Corvus::Object::ArchitectureType::x86;
		case IMAGE_FILE_MACHINE_AMD64: return Corvus::Object::ArchitectureType::x64;
		default: return Corvus::Object::ArchitectureType::Unknown;
		}
	}

	bool QuerySeDebugPrivilege32(HANDLE hProcess)
	{
		if (!Corvus::Service::IsValidHandle(hProcess)) return false;
		HANDLE hToken{};
		if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) return false;

		DWORD size{};
		GetTokenInformation(hToken, TokenPrivileges, nullptr, 0, &size);
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
		{
			Corvus::Service::CloseHandle32(hToken);
			return false;
		}

		std::vector<BYTE> buffer(size);
		if (!GetTokenInformation(hToken, TokenPrivileges, buffer.data(), size, &size))
		{
			Corvus::Service::CloseHandle32(hToken);
			return false;
		}

		bool enabled{ false };
		PTOKEN_PRIVILEGES tPriv{
			reinterpret_cast<PTOKEN_PRIVILEGES>(buffer.data()) };

		for (DWORD i = 0; i < tPriv->PrivilegeCount; ++i)
		{
			LUID_AND_ATTRIBUTES laa = tPriv->Privileges[i];
			WCHAR processName[256] = {};
			DWORD nameLen = _countof(processName);

			if (LookupPrivilegeNameW(nullptr, &laa.Luid, processName, &nameLen))
			{
				if (_wcsicmp(processName, SE_DEBUG_NAME) == 0)
				{
					enabled = (laa.Attributes & SE_PRIVILEGE_ENABLED) != 0;
					break;
				}
			}
		}

		Corvus::Service::CloseHandle32(hToken);
		return enabled;
	}

	int QueryThreadPriority32(HANDLE hThread)
	{
		return GetThreadPriority(hThread);
	}
#pragma endregion
	/*
	std::vector<Corvus::Object::ProcessEntry> WindowsProvider32::QueryProcesses()
	{
		HANDLE hProcessSnapshot{ CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
		if (!Corvus::Service::IsValidHandle(hProcessSnapshot)) return {};

		PROCESSENTRY32W pEntry32W{};
		pEntry32W.dwSize = sizeof(PROCESSENTRY32W);

		std::vector<Corvus::Object::ProcessEntry> processList{};
		if (Process32FirstW(hProcessSnapshot, &pEntry32W))
		{
			do
			{
				Corvus::Object::ProcessEntry pEntry{};
				pEntry.processId = pEntry32W.th32ProcessID;
				pEntry.processName = pEntry32W.szExeFile;
				pEntry.parentProcessId = pEntry32W.th32ParentProcessID;
				QueryModuleBaseAddress(pEntry.processId, pEntry.processName);
				QueryVisibleWindow(pEntry.processId);

				const ACCESS_MASK accessMasks[]
				{
					PROCESS_ALL_ACCESS,
					PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
					PROCESS_QUERY_LIMITED_INFORMATION
				};

				HANDLE hProc{};
				for (ACCESS_MASK accessMask : accessMasks)
				{
					hProc = OpenProcessHandle(pEntry.processId, accessMask);
					if (Corvus::Service::IsValidHandle(hProc)) break;
				}

				HANDLE hModuleSnapshot{
					CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
						pEntry.processId) };

				QueryImageFilePath(hProc);
				QueryPriorityClass(hProc);
				BOOL isWow64{ FALSE };
				QueryArchitecture(hProc, isWow64);

				if (Corvus::Service::IsValidHandle(hProc))
					CloseProcessHandle(hProc);
			} while (Process32NextW(hProcessSnapshot, &pEntry32W));
		}
		return processList;
	}
	*/
}