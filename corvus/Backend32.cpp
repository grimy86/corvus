#include "Backend32.h"
#include "MemoryService.h"
#include "MemoryService32.h"
#include "ProcessObject.h"
#include <TlHelp32.h>
#include <Psapi.h>

namespace Corvus::Data
{
	HANDLE Backend32::OpenProcessHandle(const DWORD processId, const ACCESS_MASK accessMask)
	{
		return Corvus::Service::OpenHandle32(processId, accessMask);
	}

	BOOL Backend32::CloseProcessHandle(HANDLE handle)
	{
		return Corvus::Service::CloseHandle32(handle);
	}

	std::vector<Corvus::Object::ProcessEntry> Backend32::QueryProcesses()
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

	Corvus::Object::ProcessEntry Backend32::QueryProcessInfo(HANDLE hProcess, DWORD processId)
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

	std::vector<Corvus::Object::ModuleEntry> Backend32::QueryModules(const Corvus::Object::ProcessObject& Object)
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

	std::vector<Corvus::Object::ThreadEntry> Backend32::QueryThreads(const Corvus::Object::ProcessObject& Object)
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

	std::vector<Corvus::Object::HandleEntry> Backend32::QueryHandles(const Corvus::Object::ProcessObject& Object)
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

	std::wstring Backend32::QueryImageFilePath(HANDLE hProcess)
	{
		std::wstring iFilePathBuffer{};
		iFilePathBuffer.resize(32768);
		DWORD size = static_cast<DWORD>(iFilePathBuffer.size());

		if (!QueryFullProcessImageNameW(hProcess, 0, iFilePathBuffer.data(), &size)) return L"";
		iFilePathBuffer.resize(size);

		return iFilePathBuffer;
	}

	uintptr_t Backend32::QueryModuleBaseAddress(const DWORD processId, const std::wstring& processName)
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

	Corvus::Object::UserProcessBasePriorityClass Backend32::QueryPriorityClass(HANDLE hProcess)
	{
		return static_cast<Corvus::Object::UserProcessBasePriorityClass>(::GetPriorityClass(hProcess));
	}

	bool Backend32::QueryVisibleWindow(const DWORD processId)
	{
		for (HWND hwnd = GetTopWindow(nullptr); hwnd; hwnd = GetNextWindow(hwnd, GW_HWNDNEXT))
		{
			DWORD windowThreadProcessId{};
			GetWindowThreadProcessId(hwnd, &windowThreadProcessId);
			if (windowThreadProcessId == processId && IsWindowVisible(hwnd)) return true;
		}
		return false;
	}

	Corvus::Object::ArchitectureType Backend32::QueryArchitecture(HANDLE hProcess, BOOL& isWow64)
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

	bool Backend32::QuerySeDebugPrivilege32(HANDLE hProcess)
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

	int Backend32::QueryThreadPriority32(HANDLE hThread)
	{
		return GetThreadPriority(hThread);
	}
}