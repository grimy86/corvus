#include "process.hpp"
#include <TlHelp32.h>
#include <Psapi.h>
#include <sstream>
#pragma comment(lib, "ntdll.lib")

namespace corvus::process
{
#pragma region Structures
	ProcessQueryContext::~ProcessQueryContext()
	{
		if (hProcessSnapshot != INVALID_HANDLE_VALUE)
			CloseHandle(hProcessSnapshot);
		if (hModuleSnapshot != INVALID_HANDLE_VALUE)
			CloseHandle(hModuleSnapshot);
		if (hThreadSnapshot != INVALID_HANDLE_VALUE)
			CloseHandle(hThreadSnapshot);
		if (hProcess)
			CloseHandle(hProcess);
	}
#pragma endregion

#pragma region Interface & Base
	const std::wstring& WindowsProcessBase::GetName() const noexcept { return m_name; }
	const std::wstring& WindowsProcessBase::GetImageFilePath() const noexcept { return m_imageFilePath; }
	const std::vector<ModuleEntry>& WindowsProcessBase::GetModules() const noexcept { return m_modules; }
	const std::vector<ThreadEntry>& WindowsProcessBase::GetThreads() const noexcept { return m_threads; }
	const std::vector<HandleEntry>& WindowsProcessBase::GetHandles() const noexcept { return m_handles; }
	uintptr_t WindowsProcessBase::GetModuleBaseAddress() const noexcept { return m_moduleBaseAddress; }
	uintptr_t WindowsProcessBase::GetPEBAddress() const noexcept { return m_pebAddress; }
	DWORD WindowsProcessBase::GetProcessId() const noexcept { return m_processId; }
	DWORD WindowsProcessBase::GetParentProcessId() const noexcept { return m_parentProcessId; }
	DWORD WindowsProcessBase::GetPriorityClass() const noexcept { return m_priorityClass; }
	LONG WindowsProcessBase::GetBasePriority() const noexcept { return m_basePriority; }
	BOOL WindowsProcessBase::IsWow64() const noexcept { return m_isWow64; }
	BOOL WindowsProcessBase::IsProtectedProcess() const noexcept { return m_isProtectedProcess; }
	BOOL WindowsProcessBase::IsBackgroundProcess() const noexcept { return m_isBackgroundProcess; }
	BOOL WindowsProcessBase::IsSecureProcess() const noexcept { return m_isSecureProcess; }
	BOOL WindowsProcessBase::IsSubsystemProcess() const noexcept { return m_isSubsystemProcess; }
	BOOL WindowsProcessBase::HasVisibleWindow() const noexcept { return m_hasVisibleWindow; }
	ArchitectureType WindowsProcessBase::GetArchitectureType() const noexcept { return m_architectureType; }
	const std::string& WindowsProcessBase::GetNameA() const noexcept { return ToString(m_name); }
	const std::string& WindowsProcessBase::GetImageFilePathA() const noexcept { return ToString(m_imageFilePath); }
	const char* WindowsProcessBase::GetPriorityClassA() const noexcept { return ToString(m_priorityClass); }
	const char* WindowsProcessBase::GetArchitectureTypeA() const noexcept { return ToString(m_architectureType); }

	bool WindowsProcessBase::IsValidProcessId(const DWORD processId) noexcept { return processId % 4 == 0; }
	bool WindowsProcessBase::IsValidModuleBaseAddress(const DWORD moduleBaseAddress) noexcept { return moduleBaseAddress != ERROR_INVALID_ADDRESS; }
	bool WindowsProcessBase::IsValidHandle(const HANDLE handle) noexcept
	{
		return (handle != nullptr &&
			handle != reinterpret_cast<HANDLE>(-1) &&
			handle != INVALID_HANDLE_VALUE);
	}

	std::string WindowsProcessBase::ToString(const std::wstring& w) noexcept
	{
		if (w.empty())
			return {};

		int size = WideCharToMultiByte(
			CP_UTF8, 0,
			w.data(), (int)w.size(),
			nullptr, 0,
			nullptr, nullptr
		);

		std::string result(size, '\0');

		WideCharToMultiByte(
			CP_UTF8, 0,
			w.data(), (int)w.size(),
			result.data(), size,
			nullptr, nullptr
		);

		return result;
	}
	const char* WindowsProcessBase::ToString(ArchitectureType arch) noexcept
	{
		switch (arch)
		{
		case ArchitectureType::Unknown: return "Unknown";
		case ArchitectureType::x86: return "x86";
		case ArchitectureType::x64: return "x64";
		case ArchitectureType::arm: return "ARM";
		case ArchitectureType::arm64: return "ARM64";
		default: return "Unknown";
		}
	}
	const char* WindowsProcessBase::ToString(const DWORD& priorityClass) noexcept
	{
		switch (priorityClass)
		{
		case NORMAL_PRIORITY_CLASS: return "Normal";
		case IDLE_PRIORITY_CLASS: return "Idle";
		case HIGH_PRIORITY_CLASS: return "High";
		case REALTIME_PRIORITY_CLASS: return "Realtime";
		case BELOW_NORMAL_PRIORITY_CLASS: return "Below normal";
		case ABOVE_NORMAL_PRIORITY_CLASS: return "Above normal";
		default: return "Unknown";
		}
	}
	const char* DecodeAccessBits(DWORD access, const AccessBit* bits, size_t count) noexcept
	{
		static std::string buffer;
		buffer.clear();

		bool first = true;
		for (size_t i = 0; i < count; ++i)
		{
			if (access & bits[i].bit)
			{
				if (!first)
					buffer += " | ";
				buffer += bits[i].name;
				first = false;
			}
		}

		return first ? "NONE" : buffer.c_str();
	}
	const char* WindowsProcessBase::ToString(PSS_OBJECT_TYPE type, DWORD access) noexcept
	{
		// No access
		if (!access) return "";

		switch (type)
		{
		case PSS_OBJECT_TYPE_PROCESS:
		{
			static const AccessBit bits[] = {
			{ PROCESS_TERMINATE,                 "PROCESS_TERMINATE" },
			{ PROCESS_CREATE_THREAD,             "PROCESS_CREATE_THREAD" },
			{ PROCESS_SET_SESSIONID,             "PROCESS_SET_SESSIONID" },
			{ PROCESS_VM_OPERATION,              "PROCESS_VM_OPERATION" },
			{ PROCESS_VM_READ,                   "PROCESS_VM_READ" },
			{ PROCESS_VM_WRITE,                  "PROCESS_VM_WRITE" },
			{ PROCESS_DUP_HANDLE,                "PROCESS_DUP_HANDLE" },
			{ PROCESS_CREATE_PROCESS,            "PROCESS_CREATE_PROCESS" },
			{ PROCESS_SET_QUOTA,                 "PROCESS_SET_QUOTA" },
			{ PROCESS_SET_INFORMATION,           "PROCESS_SET_INFORMATION" },
			{ PROCESS_QUERY_INFORMATION,         "PROCESS_QUERY_INFORMATION" },
			{ PROCESS_SUSPEND_RESUME,             "PROCESS_SUSPEND_RESUME" },
			{ PROCESS_QUERY_LIMITED_INFORMATION, "PROCESS_QUERY_LIMITED_INFORMATION" },

			{ DELETE,        "DELETE" },
			{ READ_CONTROL,  "READ_CONTROL" },
			{ WRITE_DAC,     "WRITE_DAC" },
			{ WRITE_OWNER,   "WRITE_OWNER" },
			{ SYNCHRONIZE,   "SYNCHRONIZE" },
			};

			if ((access & PROCESS_ALL_ACCESS) == PROCESS_ALL_ACCESS)
			{
				return "PROCESS_ALL_ACCESS";
			}

			return DecodeAccessBits(access, bits, std::size(bits));
		}
		case PSS_OBJECT_TYPE_THREAD:
		{
			static const AccessBit bits[] = {
			{ THREAD_TERMINATE,                 "THREAD_TERMINATE" },
			{ THREAD_SUSPEND_RESUME,            "THREAD_SUSPEND_RESUME" },
			{ THREAD_GET_CONTEXT,               "THREAD_GET_CONTEXT" },
			{ THREAD_SET_CONTEXT,               "THREAD_SET_CONTEXT" },
			{ THREAD_SET_INFORMATION,           "THREAD_SET_INFORMATION" },
			{ THREAD_QUERY_INFORMATION,         "THREAD_QUERY_INFORMATION" },
			{ THREAD_SET_THREAD_TOKEN,          "THREAD_SET_THREAD_TOKEN" },
			{ THREAD_IMPERSONATE,               "THREAD_IMPERSONATE" },
			{ THREAD_DIRECT_IMPERSONATION,      "THREAD_DIRECT_IMPERSONATION" },
			{ THREAD_QUERY_LIMITED_INFORMATION, "THREAD_QUERY_LIMITED_INFORMATION" },

			{ DELETE,        "DELETE" },
			{ READ_CONTROL,  "READ_CONTROL" },
			{ WRITE_DAC,     "WRITE_DAC" },
			{ WRITE_OWNER,   "WRITE_OWNER" },
			{ SYNCHRONIZE,   "SYNCHRONIZE" },
			};

			if ((access & THREAD_ALL_ACCESS) == THREAD_ALL_ACCESS)
			{
				return "THREAD_ALL_ACCESS";
			}

			return DecodeAccessBits(access, bits, std::size(bits));
		}
		case PSS_OBJECT_TYPE_SECTION:
		{
			static const AccessBit bits[] = {
			{ SECTION_QUERY,        "SECTION_QUERY" },
			{ SECTION_MAP_READ,     "SECTION_MAP_READ" },
			{ SECTION_MAP_WRITE,    "SECTION_MAP_WRITE" },
			{ SECTION_MAP_EXECUTE,  "SECTION_MAP_EXECUTE" },
			{ SECTION_EXTEND_SIZE,  "SECTION_EXTEND_SIZE" },

			{ DELETE,        "DELETE" },
			{ READ_CONTROL,  "READ_CONTROL" },
			{ WRITE_DAC,     "WRITE_DAC" },
			{ WRITE_OWNER,   "WRITE_OWNER" },
			{ SYNCHRONIZE,   "SYNCHRONIZE" },
			};

			if ((access & SECTION_ALL_ACCESS) == SECTION_ALL_ACCESS)
			{
				return "SECTION_ALL_ACCESS";
			}

			return DecodeAccessBits(access, bits, std::size(bits));
		}
		case PSS_OBJECT_TYPE_EVENT:
		{
			static const AccessBit bits[] = {
			{ EVENT_MODIFY_STATE, "EVENT_MODIFY_STATE" },

			{ DELETE,        "DELETE" },
			{ READ_CONTROL,  "READ_CONTROL" },
			{ WRITE_DAC,     "WRITE_DAC" },
			{ WRITE_OWNER,   "WRITE_OWNER" },
			{ SYNCHRONIZE,   "SYNCHRONIZE" },
			};

			if ((access & EVENT_ALL_ACCESS) == EVENT_ALL_ACCESS)
			{
				return "EVENT_ALL_ACCESS";
			}

			return DecodeAccessBits(access, bits, std::size(bits));
		}
		case PSS_OBJECT_TYPE_MUTANT:
		{
			static const AccessBit bits[] = {
			{ MUTANT_QUERY_STATE, "MUTANT_QUERY_STATE" },

			{ DELETE,        "DELETE" },
			{ READ_CONTROL,  "READ_CONTROL" },
			{ WRITE_DAC,     "WRITE_DAC" },
			{ WRITE_OWNER,   "WRITE_OWNER" },
			{ SYNCHRONIZE,   "SYNCHRONIZE" },
			};

			if ((access & MUTANT_ALL_ACCESS) == MUTANT_ALL_ACCESS)
			{
				return "MUTANT_ALL_ACCESS";
			}

			return DecodeAccessBits(access, bits, std::size(bits));
		}
		case PSS_OBJECT_TYPE_SEMAPHORE:
		{
			static const AccessBit bits[] = {
			{ SEMAPHORE_MODIFY_STATE, "SEMAPHORE_MODIFY_STATE" },

			{ DELETE,        "DELETE" },
			{ READ_CONTROL,  "READ_CONTROL" },
			{ WRITE_DAC,     "WRITE_DAC" },
			{ WRITE_OWNER,   "WRITE_OWNER" },
			{ SYNCHRONIZE,   "SYNCHRONIZE" },
			};

			if ((access & SEMAPHORE_ALL_ACCESS) == SEMAPHORE_ALL_ACCESS)
			{
				return "SEMAPHORE_ALL_ACCESS";
			}

			return DecodeAccessBits(access, bits, std::size(bits));
		}
		default:
			break;
		}

		// Unknown object
		static char buffer[16];
		std::snprintf(buffer, sizeof(buffer), "0x%08X", access);
		return buffer;
	}

	WindowsProcessBase::WindowsProcessBase(const DWORD processId)
		: m_processId(processId)
	{
		if (!IsValidProcessId(processId))
			throw std::invalid_argument("Invalid PID");
	}
#pragma endregion

#pragma region Implementation: WindowsProcessWin32
	void WindowsProcessWin32::QueryModulesW32(HANDLE hProcess, const HANDLE& hModuleSnapshot, WindowsProcessWin32& proc)
	{
		MODULEINFO mInfoBuffer{};
		MODULEENTRY32W mEntry{};
		mEntry.dwSize = sizeof(mEntry);

		if (!Module32FirstW(hModuleSnapshot, &mEntry)) return;
		do
		{
			if (!K32GetModuleInformation(
				hProcess,
				reinterpret_cast<HMODULE>(mEntry.modBaseAddr),
				&mInfoBuffer,
				sizeof(mInfoBuffer)))
				continue;

			ModuleEntry module{};
			module.moduleName = mEntry.szModule;
			module.modulePath = mEntry.szExePath;
			module.size = mEntry.dwSize;
			module.baseAddress = reinterpret_cast<uintptr_t>(mEntry.modBaseAddr);
			module.moduleBaseSize = mEntry.modBaseSize;
			module.entryPoint = mInfoBuffer.EntryPoint;
			module.processId = mEntry.th32ProcessID;
			module.globalLoadCount = mEntry.GlblcntUsage;
			module.processLoadCount = mEntry.ProccntUsage;
			proc.m_modules.push_back(module);

		} while (Module32NextW(hModuleSnapshot, &mEntry));
	}

	void WindowsProcessWin32::QueryThreadsW32(HANDLE hThreadSnapshot, WindowsProcessWin32& proc)
	{
		THREADENTRY32 tEntry{};
		tEntry.dwSize = sizeof(THREADENTRY32);
		if (Thread32First(hThreadSnapshot, &tEntry))
		{
			do
			{
				if (tEntry.th32OwnerProcessID != proc.m_processId) continue;

				ThreadEntry thread{};
				thread.size = tEntry.dwSize;
				thread.threadId = tEntry.th32ThreadID;
				thread.ownerProcessId = tEntry.th32OwnerProcessID;
				thread.basePriority = tEntry.tpBasePri; //KeQueryPriorityThread
				proc.m_threads.push_back(thread);

			} while (Thread32Next(hThreadSnapshot, &tEntry));
		}
	}

	void WindowsProcessWin32::QueryHandlesW32(HANDLE hProcess, WindowsProcessWin32& proc)
	{
		HPSS pssSnapshot = nullptr;
		HPSSWALK hWalkMarker = nullptr;

		const PSS_CAPTURE_FLAGS captureFlags =
			PSS_CAPTURE_HANDLES |
			PSS_CAPTURE_HANDLE_NAME_INFORMATION |
			PSS_CAPTURE_HANDLE_BASIC_INFORMATION |
			PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION |
			PSS_CAPTURE_HANDLE_TRACE;

		if (PssCaptureSnapshot(
			hProcess,
			captureFlags,
			0,
			&pssSnapshot) != ERROR_SUCCESS)
		{
			return;
		}

		if (PssWalkMarkerCreate(nullptr, &hWalkMarker) != ERROR_SUCCESS)
		{
			PssFreeSnapshot(GetCurrentProcess(), pssSnapshot);
			return;
		}

		while (true)
		{
			PSS_HANDLE_ENTRY handleBuffer{};
			const DWORD walkStatus = PssWalkSnapshot(
				pssSnapshot,
				PSS_WALK_HANDLES,
				hWalkMarker,
				&handleBuffer,
				sizeof(handleBuffer)
			);

			if (walkStatus == ERROR_NO_MORE_ITEMS)
				break;

			if (walkStatus != ERROR_SUCCESS)
				break;

			HandleEntry handle{};
			handle.typeName = handleBuffer.TypeName ? handleBuffer.TypeName : L"Unknown";
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
				handle.targetProcessId = handleBuffer.TypeSpecificInformation.Process.ProcessId;
				break;

			case PSS_OBJECT_TYPE_THREAD:
				handle.targetProcessId = handleBuffer.TypeSpecificInformation.Thread.ProcessId;
				break;

			case PSS_OBJECT_TYPE_MUTANT:
				handle.targetProcessId = handleBuffer.TypeSpecificInformation.Mutant.OwnerProcessId;
				break;

			default:
				handle.targetProcessId = 0; // not applicable
				break;
			}

			proc.m_handles.push_back(handle);
		}

		PssWalkMarkerFree(hWalkMarker);
		PssFreeSnapshot(GetCurrentProcess(), pssSnapshot);
	}

	void WindowsProcessWin32::QueryArchitectureW32(HANDLE hProcess, WindowsProcessWin32& proc)
	{
		// The instruction set the process image targets
		USHORT processMachine{ IMAGE_FILE_MACHINE_UNKNOWN };

		// The actual CPU architecture of the OS kernel
		USHORT nativeMachine{ IMAGE_FILE_MACHINE_UNKNOWN };

		if (!IsWow64Process2(hProcess, &processMachine, &nativeMachine))
		{
			proc.m_architectureType = ArchitectureType::Unknown;
			proc.m_isWow64 = FALSE;
			return;
		}

		// emulation check
		proc.m_isWow64 = (processMachine != IMAGE_FILE_MACHINE_UNKNOWN);

		// determine effective architecture
		const USHORT machine{
			proc.m_isWow64 ? processMachine : nativeMachine };

		switch (machine)
		{
		case IMAGE_FILE_MACHINE_UNKNOWN:
			proc.m_architectureType = ArchitectureType::Unknown;
			break;
		case IMAGE_FILE_MACHINE_I386:
			proc.m_architectureType = ArchitectureType::x86;
			break;
		case IMAGE_FILE_MACHINE_AMD64:
			proc.m_architectureType = ArchitectureType::x64;
			break;
		case IMAGE_FILE_MACHINE_ARM:
			proc.m_architectureType = ArchitectureType::arm;
			break;
		case IMAGE_FILE_MACHINE_ARM64:
			proc.m_architectureType = ArchitectureType::arm64;
			break;
		default:
			proc.m_architectureType = ArchitectureType::Unknown;
			break;
		}
	}

	void WindowsProcessWin32::QueryVisibleWindowW32(WindowsProcessWin32& proc)
	{
		for (HWND hwnd = GetTopWindow(nullptr); hwnd; hwnd = GetNextWindow(hwnd, GW_HWNDNEXT))
		{
			DWORD pid = 0;
			GetWindowThreadProcessId(hwnd, &pid);

			if (pid == proc.m_processId && IsWindowVisible(hwnd))
			{
				proc.m_hasVisibleWindow = TRUE;
			}
		}
	}

	void WindowsProcessWin32::QueryModuleBaseAddressW32(HANDLE hModuleSnapshot, WindowsProcessWin32& proc)
	{
		uintptr_t moduleBaseAddress{};
		MODULEENTRY32W mEntry{};
		mEntry.dwSize = sizeof(MODULEENTRY32W);

		if (!Module32First(hModuleSnapshot, &mEntry)) return;

		do
		{
			if (mEntry.szModule == proc.m_name)
			{
				proc.m_moduleBaseAddress = reinterpret_cast<uintptr_t>(mEntry.modBaseAddr);
			}
		} while (Module32Next(hModuleSnapshot, &mEntry));
	}

	void WindowsProcessWin32::QueryImageFilePathW32(HANDLE hProcess, WindowsProcessWin32& proc)
	{
		std::wstring iFilePathBuffer;
		iFilePathBuffer.resize(32768);
		DWORD size = static_cast<DWORD>(iFilePathBuffer.size());

		if (QueryFullProcessImageNameW(hProcess, 0, iFilePathBuffer.data(), &size)) {
			iFilePathBuffer.resize(size);
			proc.m_imageFilePath = iFilePathBuffer;
		}
	}

	void WindowsProcessWin32::QueryPriorityClassW32(HANDLE hProcess, WindowsProcessWin32& proc)
	{
		proc.m_priorityClass = ::GetPriorityClass(hProcess);
	}

	std::vector<WindowsProcessWin32> WindowsProcessWin32::GetProcessListW32()
	{
		ProcessQueryContext snapshotCtx{};
		std::vector<WindowsProcessWin32> result{};

		snapshotCtx.hProcessSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (!IsValidHandle(snapshotCtx.hProcessSnapshot)) return result;

		PROCESSENTRY32W pEntry{};
		pEntry.dwSize = sizeof(PROCESSENTRY32W);

		if (Process32FirstW(snapshotCtx.hProcessSnapshot, &pEntry))
		{
			do
			{
				ProcessQueryContext processCtx{};
				WindowsProcessWin32 proc{ pEntry.th32ProcessID };
				proc.m_name = pEntry.szExeFile;
				proc.m_parentProcessId = pEntry.th32ParentProcessID;

				HANDLE hProc{ OpenProcessHandleW32(
					pEntry.th32ProcessID,
					PROCESS_ALL_ACCESS) };

				if (!IsValidHandle(hProc))
				{
					hProc = OpenProcessHandleW32(
						pEntry.th32ProcessID,
						PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);
				}

				if (!IsValidHandle(hProc))
				{
					hProc = OpenProcessHandleW32(
						pEntry.th32ProcessID,
						PROCESS_QUERY_LIMITED_INFORMATION);
				}

				if (!IsValidHandle(hProc)) continue;

				processCtx.hProcess = hProc;

				processCtx.hModuleSnapshot = CreateToolhelp32Snapshot(
					TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
					pEntry.th32ProcessID);
				if (!IsValidHandle(processCtx.hModuleSnapshot))
					processCtx.hModuleSnapshot = nullptr;

				processCtx.hThreadSnapshot = CreateToolhelp32Snapshot(
					TH32CS_SNAPTHREAD,
					pEntry.th32ProcessID);
				if (!IsValidHandle(processCtx.hThreadSnapshot))
					processCtx.hThreadSnapshot = nullptr;

				QueryImageFilePathW32(processCtx.hProcess, proc);
				QueryThreadsW32(processCtx.hThreadSnapshot, proc);
				QueryModulesW32(processCtx.hProcess, processCtx.hModuleSnapshot, proc);
				QueryHandlesW32(processCtx.hProcess, proc);
				QueryModuleBaseAddressW32(processCtx.hModuleSnapshot, proc);
				QueryPriorityClassW32(processCtx.hProcess, proc);
				QueryArchitectureW32(processCtx.hProcess, proc);
				QueryVisibleWindowW32(proc);

				result.push_back(proc);

			} while (Process32NextW(snapshotCtx.hProcessSnapshot, &pEntry));
		}
		return result;
	}

	HANDLE WindowsProcessWin32::OpenProcessHandleW32(const DWORD processId, const ACCESS_MASK accessMask)
	{
		return OpenProcess(accessMask, FALSE, processId);
	}

	uintptr_t WindowsProcessWin32::GetModuleBaseAddressW32(HANDLE hModuleSnapshot, WindowsProcessWin32& proc)
	{
		uintptr_t moduleBaseAddress{};
		MODULEENTRY32W mEntry{};
		mEntry.dwSize = sizeof(MODULEENTRY32W);
		if (!Module32First(hModuleSnapshot, &mEntry))
		{
			return moduleBaseAddress;
		}

		do
		{
			if (mEntry.szModule != proc.m_name)
			{
				CloseHandle(hModuleSnapshot);
				return reinterpret_cast<uintptr_t>(mEntry.modBaseAddr);
			}
		} while (Module32Next(hModuleSnapshot, &mEntry));

		CloseHandle(hModuleSnapshot);
		return moduleBaseAddress;
	}

	std::string WindowsProcessWin32::GetProcessNameW32(DWORD pid)
	{
		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (snapshot == INVALID_HANDLE_VALUE)
			return {};

		PROCESSENTRY32W pe{};
		pe.dwSize = sizeof(pe);

		if (Process32FirstW(snapshot, &pe))
		{
			do
			{
				if (pe.th32ProcessID == pid)
				{
					// Wide → UTF-8
					int size = WideCharToMultiByte(
						CP_UTF8,
						0,
						pe.szExeFile,
						-1,
						nullptr,
						0,
						nullptr,
						nullptr
					);

					std::string result(size - 1, '\0');

					WideCharToMultiByte(
						CP_UTF8,
						0,
						pe.szExeFile,
						-1,
						result.data(),
						size,
						nullptr,
						nullptr
					);

					CloseHandle(snapshot);
					return result;
				}
			} while (Process32NextW(snapshot, &pe));
		}

		CloseHandle(snapshot);
		return {};
	}

	BOOL  WindowsProcessWin32::SuspendThreadW32(const DWORD threadId)
	{
		HANDLE hThread{ OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadId) };
		if (!hThread) return FALSE;
		SuspendThread(hThread);
		CloseHandle(hThread);
		return TRUE;
	}

	BOOL WindowsProcessWin32::ResumeThreadW32(const DWORD threadId)
	{
		HANDLE hThread{ OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadId) };
		if (!hThread) return FALSE;
		ResumeThread(hThread);
		CloseHandle(hThread);
		return TRUE;
	}

	void WindowsProcessWin32::PatchExecutionEW32(HANDLE processHandle, DWORD destination, BYTE* value, unsigned int size)
	{
		// Changes the protection on a region of committed pages in the virtual address space of a specified process.
		// https://learn.microsoft.com/en-us/windows/win32/Memory/memory-protection-constants

		DWORD oldPageProtection;
		VirtualProtectEx(processHandle, (void*)destination, size, PAGE_EXECUTE_READWRITE, &oldPageProtection);
		WriteProcessMemory(processHandle, (void*)destination, value, size, nullptr);
	}

	void WindowsProcessWin32::NopExecutionEW32(HANDLE processHandle, DWORD destination, unsigned int size)
	{
		// Filling an array with x86 NOP instructions (0x90)
		BYTE* noOperationArray = new BYTE[size];
		memset(noOperationArray, 0x90, size);

		PatchExecutionEW32(processHandle, destination, noOperationArray, size);
		delete[] noOperationArray;
	}

	// Find multi-level pointers (external)
	DWORD WindowsProcessWin32::FindDMAAddyEW32(HANDLE processHandle, DWORD ptr, std::vector<DWORD> offsets)
	{
		DWORD addr{ ptr };
		for (unsigned int i = 0; i < offsets.size(); ++i)
		{
			ReadProcessMemory(processHandle, (void*)addr, &addr, sizeof(addr), nullptr);
			addr += offsets[i];
		}
		return addr;
	}

	//Internal patch function, uses VirtualProtect instead of VirtualProtectEx
	void WindowsProcessWin32::PatchExecutionIW32(DWORD destination, BYTE* value, unsigned int size)
	{
		DWORD oldPageProtection;
		VirtualProtect((void*)destination, size, PAGE_EXECUTE_READWRITE, &oldPageProtection);
		memcpy((void*)destination, value, size);
		VirtualProtect((void*)destination, size, oldPageProtection, &oldPageProtection);
	}

	//Internal nop function, uses memset instead of WPM
	void  WindowsProcessWin32::NopExecutionIW32(DWORD destination, unsigned int size)
	{
		DWORD oldPageProtection;
		VirtualProtect((void*)destination, size, PAGE_EXECUTE_READWRITE, &oldPageProtection);
		memset((void*)destination, 0x90, size);
		VirtualProtect((void*)destination, size, oldPageProtection, &oldPageProtection);
	}

	// Internal Find multi-level pointers
	DWORD WindowsProcessWin32::FindDMAAddyIW32(DWORD ptr, std::vector<DWORD> offsets)
	{
		DWORD addr{ ptr };
		for (unsigned int i = 0; i < offsets.size(); ++i)
		{
			addr = *(DWORD*)addr;
			addr += offsets[i];
		}
		return addr;
	}

	BOOL WindowsProcessWin32::EnableSeDebugPrivilegeW32()
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

	BOOL WindowsProcessWin32::EnableSeDebugPrivilegeW32(const DWORD processId)
	{
		HANDLE hProc{ OpenProcessHandleW32(processId, PROCESS_ALL_ACCESS) };
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

		CloseHandle(hProc);
		return bRet;
	}

	bool WindowsProcessWin32::IsSeDebugPrivilegeEnabledW32()
	{
		HANDLE hToken = nullptr;
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
			return false;

		DWORD size = 0;
		GetTokenInformation(hToken, TokenPrivileges, nullptr, 0, &size);
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
		{
			CloseHandle(hToken);
			return false;
		}

		std::vector<BYTE> buffer(size);
		if (!GetTokenInformation(hToken, TokenPrivileges, buffer.data(), size, &size))
		{
			CloseHandle(hToken);
			return false;
		}

		bool enabled = false;
		PTOKEN_PRIVILEGES tPriv{
			reinterpret_cast<PTOKEN_PRIVILEGES>(buffer.data()) };

		for (DWORD i = 0; i < tPriv->PrivilegeCount; ++i)
		{
			LUID_AND_ATTRIBUTES laa = tPriv->Privileges[i];
			WCHAR name[256] = {};
			DWORD nameLen = _countof(name);

			if (LookupPrivilegeNameW(nullptr, &laa.Luid, name, &nameLen))
			{
				if (_wcsicmp(name, SE_DEBUG_NAME) == 0)
				{
					enabled = (laa.Attributes & SE_PRIVILEGE_ENABLED) != 0;
					break;
				}
			}
		}

		CloseHandle(hToken);
		return enabled;
	}

	BOOL WindowsProcessWin32::SetThreadPriorityW32(int priorityMask)
	{
		return SetPriorityClass(GetCurrentProcess(), priorityMask);
	}

	bool WindowsProcessWin32::IsThreadPrioritySetW32(int priorityMask)
	{
		return GetThreadPriority(GetCurrentProcess()) == priorityMask;
	}

	WindowsProcessWin32::WindowsProcessWin32(const DWORD processId)
		: WindowsProcessBase(processId) {
	}
#pragma endregion

#pragma region Implementation: WindowsProcessNt
	std::vector<WindowsProcessNt> WindowsProcessNt::GetProcessListNt()
	{
		std::vector<WindowsProcessNt> result;

		// Get required buffer sizes for NtQSI calls
		const DWORD requiredSysProcInfoBufferSize{
			GetQSIBuffferSizeNt(SystemProcessInformation) + 0x1000 };
		const DWORD requiredExtHandleInfoBufferSize{
			GetQSIBuffferSizeNt(SystemExtendedHandleInformation) + 0x1000 };

		BYTE* sysProcInfoBuffer = new BYTE[requiredSysProcInfoBufferSize];
		BYTE* extHandleInfoBuffer = new BYTE[requiredExtHandleInfoBufferSize];

		// Query system process information
		NTSTATUS ntSysStatus{ NtQuerySystemInformation(
			SystemProcessInformation,
			sysProcInfoBuffer,
			requiredSysProcInfoBufferSize,
			nullptr) };

		// Query handle information
		NTSTATUS ntHandleStatus{ NtQuerySystemInformation(
			SystemExtendedHandleInformation,
			extHandleInfoBuffer,
			requiredExtHandleInfoBufferSize,
			nullptr) };

		if (!NT_SUCCESS(ntSysStatus))
		{
			delete[] sysProcInfoBuffer;
			delete[] extHandleInfoBuffer;
			return result;
		}

		PSYSTEM_PROCESS_INFORMATION pSys =
			reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(sysProcInfoBuffer);

		PSYSTEM_HANDLE_INFORMATION_EX pHandles =
			reinterpret_cast<PSYSTEM_HANDLE_INFORMATION_EX>(extHandleInfoBuffer);

		while (pSys)
		{
			DWORD processId =
				static_cast<DWORD>(reinterpret_cast<uintptr_t>(pSys->UniqueProcessId));

			WindowsProcessNt wProcNt{ processId };

			// Process name
			wProcNt.m_name = (pSys->ImageName.Buffer)
				? pSys->ImageName.Buffer
				: L"Unknown Nt Process Name";

			// Open process
			HANDLE hProcess{ OpenProcessHandleNt(processId, PROCESS_ALL_ACCESS) };

			if (IsValidHandle(hProcess))
			{
				BYTE* pImageFileNameBuffer = new BYTE[200];
				BYTE* pExtendedInfoBuffer = new BYTE[200];

				NTSTATUS ntImageFileNameStatus = NtQueryInformationProcess(
					hProcess,
					ProcessImageFileName,
					pImageFileNameBuffer,
					200,
					nullptr);

				NTSTATUS ntProcExtendedInfoStatus = NtQueryInformationProcess(
					hProcess,
					ProcessBasicInformation,
					pExtendedInfoBuffer,
					200,
					nullptr);

				PROCESS_PRIORITY_CLASS procPriorityClassBuffer{};
				NTSTATUS ntProcPriorityClassStatus = NtQueryInformationProcess(
					hProcess,
					ProcessPriorityClass,
					&procPriorityClassBuffer,
					sizeof(procPriorityClassBuffer),
					nullptr);

				if (NT_SUCCESS(ntImageFileNameStatus) &&
					NT_SUCCESS(ntProcExtendedInfoStatus) &&
					NT_SUCCESS(ntProcPriorityClassStatus))
				{
					PUNICODE_STRING pImageFileName =
						reinterpret_cast<PUNICODE_STRING>(pImageFileNameBuffer);

					PPROCESS_EXTENDED_BASIC_INFORMATION pProcessExtendedInfo =
						reinterpret_cast<PPROCESS_EXTENDED_BASIC_INFORMATION>(pExtendedInfoBuffer);

					wProcNt.m_imageFilePath = pImageFileName->Buffer;

					wProcNt.m_pebAddress =
						reinterpret_cast<uintptr_t>(pProcessExtendedInfo->BasicInfo.PebBaseAddress);

					wProcNt.m_basePriority =
						pProcessExtendedInfo->BasicInfo.BasePriority;

					wProcNt.m_isWow64 =
						pProcessExtendedInfo->u.s.IsWow64Process;

					wProcNt.m_isProtectedProcess =
						pProcessExtendedInfo->u.s.IsProtectedProcess;

					wProcNt.m_isBackgroundProcess =
						pProcessExtendedInfo->u.s.IsBackground;

					wProcNt.m_isSecureProcess =
						pProcessExtendedInfo->u.s.IsSecureProcess;

					wProcNt.m_isSubsystemProcess =
						pProcessExtendedInfo->u.s.IsSubsystemProcess;

					wProcNt.m_priorityClass =
						procPriorityClassBuffer.PriorityClass;
				}

				delete[] pImageFileNameBuffer;
				delete[] pExtendedInfoBuffer;
				NtClose(hProcess);
			}

			// Threads
			for (ULONG i = 0; i < pSys->NumberOfThreads; ++i)
			{
				ThreadEntry threadEntry{};
				const SYSTEM_THREAD_INFORMATION& sThreadInfo = pSys->Threads[i];

				threadEntry.size = sizeof(SYSTEM_THREAD_INFORMATION);
				threadEntry.threadId =
					static_cast<DWORD>(reinterpret_cast<uintptr_t>(sThreadInfo.ClientId.UniqueThread));
				threadEntry.ownerProcessId = processId;
				threadEntry.basePriority = sThreadInfo.BasePriority;
				threadEntry.startAddress = sThreadInfo.StartAddress;
				threadEntry.threadState = sThreadInfo.ThreadState;

				wProcNt.m_threads.push_back(threadEntry);
			}

			// Handle parsing
			if (NT_SUCCESS(ntHandleStatus))
			{
				for (ULONG i = 0; i < pHandles->NumberOfHandles; ++i)
				{
					const SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX& sHandleInfo =
						pHandles->Handles[i];

					if (static_cast<uintptr_t>(sHandleInfo.UniqueProcessId) !=
						static_cast<uintptr_t>(processId))
						continue;

					HandleEntry handleEntry{};
					handleEntry.objectName = L"Unknown";
					handleEntry.typeName = L"Unknown";
					handleEntry.handle =
						reinterpret_cast<HANDLE>(sHandleInfo.HandleValue);
					handleEntry.attributes = sHandleInfo.HandleAttributes;
					handleEntry.grantedAccess = sHandleInfo.GrantedAccess;
					handleEntry.handleCount = pHandles->NumberOfHandles;

					wProcNt.m_handles.push_back(handleEntry);
				}
			}

			result.push_back(wProcNt);

			// Advance to next process (ALWAYS)
			if (pSys->NextEntryOffset)
			{
				pSys = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(
					reinterpret_cast<BYTE*>(pSys) + pSys->NextEntryOffset);
			}
			else
			{
				break;
			}
		}

		delete[] sysProcInfoBuffer;
		delete[] extHandleInfoBuffer;
		return result;
	}

	HANDLE WindowsProcessNt::OpenProcessHandleNt(const DWORD processId, const ACCESS_MASK accessMask)
	{
		HANDLE pHandle{};
		OBJECT_ATTRIBUTES objectAttributes{};
		objectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
		objectAttributes.RootDirectory = nullptr;
		objectAttributes.ObjectName = nullptr;
		objectAttributes.Attributes = 0;
		objectAttributes.SecurityDescriptor = nullptr;
		objectAttributes.SecurityQualityOfService = nullptr;

		CLIENT_ID clientId{};
		clientId.UniqueProcess = reinterpret_cast<HANDLE>(processId);
		clientId.UniqueThread = nullptr;

		NTSTATUS ntStatus{ NtOpenProcess(&pHandle, accessMask, &objectAttributes, &clientId) };
		if (NT_SUCCESS(ntStatus) && IsValidHandle(pHandle))
		{
			return pHandle;
		}
		else return nullptr;
	}

	DWORD WindowsProcessNt::GetQSIBuffferSizeNt(const SYSTEM_INFORMATION_CLASS sInfoClass)
	{
		DWORD requiredBufferSize{};

		NTSTATUS ntStatus{ NtQuerySystemInformation(
			sInfoClass,
			nullptr,
			0,
			&requiredBufferSize) };

		return requiredBufferSize;
	}

	WindowsProcessNt::WindowsProcessNt(const DWORD processId)
		: WindowsProcessBase(processId)
	{

	}
#pragma endregion
}