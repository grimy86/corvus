#include "process.hpp"
#include <TlHelp32.h>
#include <Psapi.h>
#pragma comment(lib, "ntdll.lib")

namespace corvus::process
{
#pragma region Interface & Base
	const std::wstring& WindowsProcess::GetProcessEntryName() const noexcept { return m_processEntry.name; }
	const std::string& WindowsProcess::GetProcessEntryNameA() const noexcept { return ToString(m_processEntry.name); }
	const std::wstring& WindowsProcess::GetProcessEntryImageFilePath() const noexcept { return m_processEntry.imageFilePath; }
	std::string WindowsProcess::GetProcessEntryImageFilePathA() const noexcept { return ToString(m_imageFilePath); }
	const std::vector<ModuleEntry>& WindowsProcess::GetProcessEntryModules() const noexcept { return m_modules; }
	const std::vector<ThreadEntry>& WindowsProcess::GetProcessEntryThreads() const noexcept { return m_threads; }
	const std::vector<HandleEntry>& WindowsProcess::GetProcessEntryHandles() const noexcept { return m_handles; }
	uintptr_t WindowsProcess::GetModuleBaseAddress() const noexcept { return m_moduleBaseAddress; }
	uintptr_t WindowsProcess::GetPEBAddress() const noexcept { return m_pebAddress; }
	DWORD WindowsProcess::GetProcessId() const noexcept { return m_processId; }
	std::string WindowsProcess::GetProcessIdA() const noexcept { return ToString(m_processId); }
	DWORD WindowsProcess::GetParentProcessId() const noexcept { return m_parentProcessId; }
	PriorityClass WindowsProcess::GetPriorityClass() const noexcept { return m_priorityClass; }
	const char* WindowsProcess::GetPriorityClassA() const noexcept { return ToString(m_priorityClass); }
	BOOL WindowsProcess::IsWow64() const noexcept { return m_isWow64; }
	BOOL WindowsProcess::IsProtectedProcess() const noexcept { return m_isProtectedProcess; }
	BOOL WindowsProcess::IsBackgroundProcess() const noexcept { return m_isBackgroundProcess; }
	BOOL WindowsProcess::IsSecureProcess() const noexcept { return m_isSecureProcess; }
	BOOL WindowsProcess::IsSubsystemProcess() const noexcept { return m_isSubsystemProcess; }
	BOOL WindowsProcess::HasVisibleWindow() const noexcept { return m_hasVisibleWindow; }
	ArchitectureType WindowsProcess::GetArchitectureType() const noexcept { return m_architectureType; }
	const char* WindowsProcess::GetArchitectureTypeA() const noexcept { return ToString(m_architectureType); }

	bool WindowsProcess::IsValidProcessId(const DWORD processId) noexcept { return processId % 4 == 0; }
	bool WindowsProcess::IsValidModuleBaseAddress(const DWORD moduleBaseAddress) noexcept { return moduleBaseAddress != ERROR_INVALID_ADDRESS; }
	bool WindowsProcess::IsValidHandle(const HANDLE handle) noexcept
	{
		return (handle != nullptr &&
			handle != reinterpret_cast<HANDLE>(-1) &&
			handle != INVALID_HANDLE_VALUE);
	}

	std::string WindowsProcess::ToString(const std::wstring& wstring) noexcept
	{
		if (wstring.empty())
			return std::string();

		// Get the required buffer size (including null terminator)
		int size_needed = WideCharToMultiByte(
			CP_UTF8,               // Code page (UTF-8 recommended)
			0,                     // Conversion flags
			wstring.c_str(),       // Source wide string
			static_cast<int>(wstring.size()), // Number of chars to convert
			nullptr,               // No output buffer yet
			0,                     // Request buffer size
			nullptr, nullptr       // Default chars / used flag
		);

		if (size_needed <= 0)
			return std::string(); // Conversion failed

		std::string result(size_needed, 0);

		WideCharToMultiByte(
			CP_UTF8,
			0,
			wstring.c_str(),
			static_cast<int>(wstring.size()),
			result.data(),
			size_needed,
			nullptr, nullptr
		);

		return result;
	}
	std::string WindowsProcess::ToString(DWORD processId) noexcept
	{
		return std::to_string(processId);
	}
	const char* WindowsProcess::ToString(ArchitectureType arch) noexcept
	{
		switch (arch)
		{
		case ArchitectureType::Unknown: return "Unknown";
		case ArchitectureType::x86: return "x86";
		case ArchitectureType::x64: return "x64";
		default: return "Unknown";
		}
	}
	const char* WindowsProcess::ToString(PriorityClass priorityClass) noexcept
	{
		switch (priorityClass)
		{
		case corvus::process::PriorityClass::Undefined: return "Undefined";
		case corvus::process::PriorityClass::Normal: return "Normal";
		case corvus::process::PriorityClass::Idle: return "Idle";
		case corvus::process::PriorityClass::High: return "High";
		case corvus::process::PriorityClass::Realtime: return "Realtime";
		case corvus::process::PriorityClass::BelowNormal: return "Below normal";
		case corvus::process::PriorityClass::AboveNormal: return "Above normal";
		default: return "Undefined";
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
	const char* WindowsProcess::MapAccess(std::wstring type, DWORD access) noexcept
	{
		// No access
		if (!access) return "";

		if (type == L"Process")
		{
			static const AccessBit bits[] = {
			{ PROCESS_TERMINATE, "PROCESS_TERMINATE" },
			{ PROCESS_CREATE_THREAD, "PROCESS_CREATE_THREAD" },
			{ PROCESS_SET_SESSIONID, "PROCESS_SET_SESSIONID" },
			{ PROCESS_VM_OPERATION, "PROCESS_VM_OPERATION" },
			{ PROCESS_VM_READ, "PROCESS_VM_READ" },
			{ PROCESS_VM_WRITE, "PROCESS_VM_WRITE" },
			{ PROCESS_DUP_HANDLE, "PROCESS_DUP_HANDLE" },
			{ PROCESS_CREATE_PROCESS, "PROCESS_CREATE_PROCESS" },
			{ PROCESS_SET_QUOTA, "PROCESS_SET_QUOTA" },
			{ PROCESS_SET_INFORMATION, "PROCESS_SET_INFORMATION" },
			{ PROCESS_QUERY_INFORMATION, "PROCESS_QUERY_INFORMATION" },
			{ PROCESS_SUSPEND_RESUME, "PROCESS_SUSPEND_RESUME" },
			{ PROCESS_QUERY_LIMITED_INFORMATION, "PROCESS_QUERY_LIMITED_INFORMATION" },
			{ DELETE, "DELETE" },
			{ READ_CONTROL, "READ_CONTROL" },
			{ WRITE_DAC, "WRITE_DAC" },
			{ WRITE_OWNER, "WRITE_OWNER" },
			{ SYNCHRONIZE, "SYNCHRONIZE" },
			};

			if ((access & PROCESS_ALL_ACCESS) == PROCESS_ALL_ACCESS)
			{
				return "PROCESS_ALL_ACCESS";
			}
			return DecodeAccessBits(access, bits, std::size(bits));
		}
		if (type == L"Thread")
		{
			static const AccessBit bits[] = {
			{ THREAD_TERMINATE, "THREAD_TERMINATE" },
			{ THREAD_SUSPEND_RESUME, "THREAD_SUSPEND_RESUME" },
			{ THREAD_GET_CONTEXT, "THREAD_GET_CONTEXT" },
			{ THREAD_SET_CONTEXT, "THREAD_SET_CONTEXT" },
			{ THREAD_SET_INFORMATION, "THREAD_SET_INFORMATION" },
			{ THREAD_QUERY_INFORMATION, "THREAD_QUERY_INFORMATION" },
			{ THREAD_SET_THREAD_TOKEN, "THREAD_SET_THREAD_TOKEN" },
			{ THREAD_IMPERSONATE, "THREAD_IMPERSONATE" },
			{ THREAD_DIRECT_IMPERSONATION, "THREAD_DIRECT_IMPERSONATION" },
			{ THREAD_QUERY_LIMITED_INFORMATION, "THREAD_QUERY_LIMITED_INFORMATION" },
			{ DELETE, "DELETE" },
			{ READ_CONTROL, "READ_CONTROL" },
			{ WRITE_DAC, "WRITE_DAC" },
			{ WRITE_OWNER, "WRITE_OWNER" },
			{ SYNCHRONIZE, "SYNCHRONIZE" },
			};

			if ((access & THREAD_ALL_ACCESS) == THREAD_ALL_ACCESS)
			{
				return "THREAD_ALL_ACCESS";
			}

			return DecodeAccessBits(access, bits, std::size(bits));
		}
		if (type == L"Section")
		{
			static const AccessBit bits[] = {
			{ SECTION_QUERY, "SECTION_QUERY" },
			{ SECTION_MAP_READ, "SECTION_MAP_READ" },
			{ SECTION_MAP_WRITE, "SECTION_MAP_WRITE" },
			{ SECTION_MAP_EXECUTE, "SECTION_MAP_EXECUTE" },
			{ SECTION_EXTEND_SIZE, "SECTION_EXTEND_SIZE" },
			{ DELETE, "DELETE" },
			{ READ_CONTROL, "READ_CONTROL" },
			{ WRITE_DAC, "WRITE_DAC" },
			{ WRITE_OWNER, "WRITE_OWNER" },
			{ SYNCHRONIZE, "SYNCHRONIZE" },
			};

			if ((access & SECTION_ALL_ACCESS) == SECTION_ALL_ACCESS)
			{
				return "SECTION_ALL_ACCESS";
			}

			return DecodeAccessBits(access, bits, std::size(bits));
		}
		if (type == L"Event")
		{
			static const AccessBit bits[] = {
			{ EVENT_MODIFY_STATE, "EVENT_MODIFY_STATE" },
			{ DELETE, "DELETE" },
			{ READ_CONTROL, "READ_CONTROL" },
			{ WRITE_DAC, "WRITE_DAC" },
			{ WRITE_OWNER, "WRITE_OWNER" },
			{ SYNCHRONIZE, "SYNCHRONIZE" },
			};

			if ((access & EVENT_ALL_ACCESS) == EVENT_ALL_ACCESS)
			{
				return "EVENT_ALL_ACCESS";
			}
			return DecodeAccessBits(access, bits, std::size(bits));
		}
		if (type == L"Mutant")
		{
			static const AccessBit bits[] = {
			{ MUTANT_QUERY_STATE, "MUTANT_QUERY_STATE" },
			{ DELETE, "DELETE" },
			{ READ_CONTROL, "READ_CONTROL" },
			{ WRITE_DAC, "WRITE_DAC" },
			{ WRITE_OWNER, "WRITE_OWNER" },
			{ SYNCHRONIZE, "SYNCHRONIZE" },
			};

			if ((access & MUTANT_ALL_ACCESS) == MUTANT_ALL_ACCESS)
			{
				return "MUTANT_ALL_ACCESS";
			}
			return DecodeAccessBits(access, bits, std::size(bits));
		}
		if (type == L"Semaphore")
		{
			static const AccessBit bits[] = {
			{ SEMAPHORE_MODIFY_STATE, "SEMAPHORE_MODIFY_STATE" },
			{ DELETE, "DELETE" },
			{ READ_CONTROL, "READ_CONTROL" },
			{ WRITE_DAC, "WRITE_DAC" },
			{ WRITE_OWNER, "WRITE_OWNER" },
			{ SYNCHRONIZE, "SYNCHRONIZE" },
			};

			if ((access & SEMAPHORE_ALL_ACCESS) == SEMAPHORE_ALL_ACCESS)
			{
				return "SEMAPHORE_ALL_ACCESS";
			}
			return DecodeAccessBits(access, bits, std::size(bits));
		}

		// Unknown object
		static char buffer[16];
		std::snprintf(buffer, sizeof(buffer), "0x%08X", access);
		return buffer;
	}
	const char* WindowsProcess::MapAttributes(DWORD attribute) noexcept
	{
		if (!attribute) return "";

		static const AccessBit bits[] = {
			{ OBJ_INHERIT, "OBJ_INHERIT"},
			{ OBJ_PERMANENT, "OBJ_PERMANENT" },
			{ OBJ_EXCLUSIVE, "OBJ_EXCLUSIVE" },
			{ OBJ_CASE_INSENSITIVE, "OBJ_CASE_INSENSITIVE" },
			{ OBJ_OPENIF, "OBJ_OPENIF" },
			{ OBJ_OPENLINK, "OBJ_OPENLINK" },
			{ OBJ_KERNEL_HANDLE, "OBJ_KERNEL_HANDLE" },
			{ OBJ_FORCE_ACCESS_CHECK, "OBJ_FORCE_ACCESS_CHECK" },
			{ OBJ_IGNORE_IMPERSONATED_DEVICEMAP, "OBJ_IGNORE_IMPERSONATED_DEVICEMAP" },
			{ OBJ_DONT_REPARSE, "OBJ_DONT_REPARSE" },
			{ OBJ_VALID_ATTRIBUTES, "OBJ_VALID_ATTRIBUTES" },
		};

		return DecodeAccessBits(attribute, bits, std::size(bits));
	}
#pragma endregion

#pragma region Implementation: WindowsProcessWin32
	void BackendWin32::QueryModules() noexcept
	{
		ProcessQueryContext pqc{};
		MODULEINFO mInfoBuffer{};
		MODULEENTRY32W mEntry{};
		mEntry.dwSize = sizeof(MODULEENTRY32W);

		HANDLE hProc{ OpenProcessHandleW32(m_processId, PROCESS_ALL_ACCESS) };
		if (!IsValidHandle(hProc)) hProc = OpenProcessHandleW32(m_processId, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);
		if (!IsValidHandle(hProc)) hProc = OpenProcessHandleW32(m_processId, PROCESS_QUERY_LIMITED_INFORMATION);
		if (!IsValidHandle(hProc)) return;

		pqc.hProcess = hProc;
		pqc.hModuleSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, m_processId);
		if (!IsValidHandle(pqc.hModuleSnapshot)) pqc.hModuleSnapshot = nullptr;

		if (!Module32FirstW(pqc.hModuleSnapshot, &mEntry)) return;
		do
		{
			if (!K32GetModuleInformation(
				pqc.hProcess,
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
			m_modules.push_back(module);

		} while (Module32NextW(pqc.hModuleSnapshot, &mEntry));
	}

	void BackendWin32::QueryThreads() noexcept
	{
		ProcessQueryContext pqc{};
		THREADENTRY32 tEntry{};
		tEntry.dwSize = sizeof(THREADENTRY32);

		HANDLE hProc{ OpenProcessHandleW32(m_processId, PROCESS_ALL_ACCESS) };
		if (!IsValidHandle(hProc)) hProc = OpenProcessHandleW32(m_processId, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);
		if (!IsValidHandle(hProc)) hProc = OpenProcessHandleW32(m_processId, PROCESS_QUERY_LIMITED_INFORMATION);
		if (!IsValidHandle(hProc)) return;

		pqc.hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, m_processId);
		if (!IsValidHandle(pqc.hThreadSnapshot)) pqc.hThreadSnapshot = nullptr;

		if (Thread32First(pqc.hThreadSnapshot, &tEntry))
		{
			do
			{
				if (tEntry.th32OwnerProcessID != m_processId) continue;

				ThreadEntry thread{};
				thread.size = tEntry.dwSize;
				thread.threadId = tEntry.th32ThreadID;
				thread.ownerProcessId = tEntry.th32OwnerProcessID;
				thread.basePriority = tEntry.tpBasePri; //KeQueryPriorityThread
				m_threads.push_back(thread);

			} while (Thread32Next(pqc.hThreadSnapshot, &tEntry));
		}
	}

	void BackendWin32::QueryHandles() noexcept
	{
		ProcessQueryContext pqc{};
		HPSS pssSnapshot = nullptr;
		HPSSWALK hWalkMarker = nullptr;

		const PSS_CAPTURE_FLAGS captureFlags =
			PSS_CAPTURE_HANDLES |
			PSS_CAPTURE_HANDLE_NAME_INFORMATION |
			PSS_CAPTURE_HANDLE_BASIC_INFORMATION |
			PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION |
			PSS_CAPTURE_HANDLE_TRACE;

		HANDLE hProc{ OpenProcessHandleW32(m_processId, PROCESS_ALL_ACCESS) };
		if (!IsValidHandle(hProc)) hProc = OpenProcessHandleW32(m_processId, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);
		if (!IsValidHandle(hProc)) hProc = OpenProcessHandleW32(m_processId, PROCESS_QUERY_LIMITED_INFORMATION);
		if (!IsValidHandle(hProc)) return;

		if (PssCaptureSnapshot(
			hProc,
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

			m_handles.push_back(handle);
		}

		PssWalkMarkerFree(hWalkMarker);
		PssFreeSnapshot(GetCurrentProcess(), pssSnapshot);
	}

	void BackendWin32::QueryArchitectureW32(HANDLE hProcess, BackendWin32& proc)
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
		default:
			proc.m_architectureType = ArchitectureType::Unknown;
			break;
		}
	}

	void BackendWin32::QueryVisibleWindowW32(BackendWin32& proc)
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

	void BackendWin32::QueryImageFilePathW32(HANDLE hProcess, BackendWin32& proc)
	{
		std::wstring iFilePathBuffer;
		iFilePathBuffer.resize(32768);
		DWORD size = static_cast<DWORD>(iFilePathBuffer.size());

		if (QueryFullProcessImageNameW(hProcess, 0, iFilePathBuffer.data(), &size)) {
			iFilePathBuffer.resize(size);
			proc.m_imageFilePath = iFilePathBuffer;
		}
	}

	void BackendWin32::QueryPriorityClassW32(HANDLE hProcess, BackendWin32& proc)
	{
		proc.m_priorityClass = static_cast<PriorityClass>(::GetPriorityClass(hProcess));
	}

	void BackendWin32::QueryModuleBaseAddressW32(HANDLE hModuleSnapshot, BackendWin32& proc)
	{
		if (!IsValidHandle(hModuleSnapshot)) return;

		MODULEENTRY32W mEntry{};
		mEntry.dwSize = sizeof(MODULEENTRY32W);

		if (!Module32First(hModuleSnapshot, &mEntry)) return;
		do
		{
			if (_wcsicmp(mEntry.szModule, proc.m_name.c_str()) == 0)
			{
				proc.m_moduleBaseAddress = reinterpret_cast<uintptr_t>(mEntry.modBaseAddr);
				return;
			}
		} while (Module32Next(hModuleSnapshot, &mEntry));
	}

	std::vector<BackendWin32> BackendWin32::GetProcessListW32()
	{
		ProcessQueryContext snapshotPqc{};
		std::vector<BackendWin32> result{};

		snapshotPqc.hProcessSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (!IsValidHandle(snapshotPqc.hProcessSnapshot)) return result;

		PROCESSENTRY32W pEntry{};
		pEntry.dwSize = sizeof(PROCESSENTRY32W);

		if (Process32FirstW(snapshotPqc.hProcessSnapshot, &pEntry))
		{
			do
			{
				ProcessQueryContext pqc{};
				BackendWin32 proc{ pEntry.th32ProcessID };
				proc.m_name = pEntry.szExeFile;
				proc.m_parentProcessId = pEntry.th32ParentProcessID;

				HANDLE hProc{ OpenProcessHandleW32(pEntry.th32ProcessID, PROCESS_ALL_ACCESS) };
				if (!IsValidHandle(hProc)) hProc = OpenProcessHandleW32(pEntry.th32ProcessID, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);
				if (!IsValidHandle(hProc)) hProc = OpenProcessHandleW32(pEntry.th32ProcessID, PROCESS_QUERY_LIMITED_INFORMATION);
				if (!IsValidHandle(hProc)) continue;
				pqc.hProcess = hProc;

				pqc.hModuleSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, proc.m_processId);

				QueryImageFilePathW32(pqc.hProcess, proc);
				QueryModuleBaseAddressW32(pqc.hModuleSnapshot, proc);
				QueryPriorityClassW32(pqc.hProcess, proc);
				QueryArchitectureW32(pqc.hProcess, proc);
				QueryVisibleWindowW32(proc);

				result.push_back(proc);

			} while (Process32NextW(snapshotPqc.hProcessSnapshot, &pEntry));
		}
		return result;
	}

	HANDLE BackendWin32::OpenProcessHandleW32(const DWORD processId, const ACCESS_MASK accessMask)
	{
		return OpenProcess(accessMask, FALSE, processId);
	}

	std::string BackendWin32::GetProcessNameW32(DWORD pid)
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

	BOOL  BackendWin32::SuspendThreadW32(const DWORD threadId)
	{
		HANDLE hThread{ OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadId) };
		if (!hThread) return FALSE;
		SuspendThread(hThread);
		CloseHandle(hThread);
		return TRUE;
	}

	BOOL BackendWin32::ResumeThreadW32(const DWORD threadId)
	{
		HANDLE hThread{ OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadId) };
		if (!hThread) return FALSE;
		ResumeThread(hThread);
		CloseHandle(hThread);
		return TRUE;
	}

	void BackendWin32::PatchExecutionEW32(HANDLE processHandle, DWORD destination, BYTE* value, unsigned int size)
	{
		// Changes the protection on a region of committed pages in the virtual address space of a specified process.
		// https://learn.microsoft.com/en-us/windows/win32/Memory/memory-protection-constants

		DWORD oldPageProtection;
		VirtualProtectEx(processHandle, (void*)destination, size, PAGE_EXECUTE_READWRITE, &oldPageProtection);
		WriteProcessMemory(processHandle, (void*)destination, value, size, nullptr);
	}

	void BackendWin32::NopExecutionEW32(HANDLE processHandle, DWORD destination, unsigned int size)
	{
		// Filling an array with x86 NOP instructions (0x90)
		BYTE* noOperationArray = new BYTE[size];
		memset(noOperationArray, 0x90, size);

		PatchExecutionEW32(processHandle, destination, noOperationArray, size);
		delete[] noOperationArray;
	}

	// Find multi-level pointers (external)
	DWORD BackendWin32::FindDMAAddyEW32(HANDLE processHandle, DWORD ptr, std::vector<DWORD> offsets)
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
	void BackendWin32::PatchExecutionIW32(DWORD destination, BYTE* value, unsigned int size)
	{
		DWORD oldPageProtection;
		VirtualProtect((void*)destination, size, PAGE_EXECUTE_READWRITE, &oldPageProtection);
		memcpy((void*)destination, value, size);
		VirtualProtect((void*)destination, size, oldPageProtection, &oldPageProtection);
	}

	//Internal nop function, uses memset instead of WPM
	void  BackendWin32::NopExecutionIW32(DWORD destination, unsigned int size)
	{
		DWORD oldPageProtection;
		VirtualProtect((void*)destination, size, PAGE_EXECUTE_READWRITE, &oldPageProtection);
		memset((void*)destination, 0x90, size);
		VirtualProtect((void*)destination, size, oldPageProtection, &oldPageProtection);
	}

	// Internal Find multi-level pointers
	DWORD BackendWin32::FindDMAAddyIW32(DWORD ptr, std::vector<DWORD> offsets)
	{
		DWORD addr{ ptr };
		for (unsigned int i = 0; i < offsets.size(); ++i)
		{
			addr = *(DWORD*)addr;
			addr += offsets[i];
		}
		return addr;
	}

	BOOL BackendWin32::EnableSeDebugPrivilegeW32()
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

	BOOL BackendWin32::EnableSeDebugPrivilegeW32(const DWORD processId)
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

	bool BackendWin32::IsSeDebugPrivilegeEnabledW32()
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

	BOOL BackendWin32::SetThreadPriorityW32(int priorityMask)
	{
		return SetPriorityClass(GetCurrentProcess(), priorityMask);
	}

	bool BackendWin32::IsThreadPrioritySetW32(int priorityMask)
	{
		return GetThreadPriority(GetCurrentProcess()) == priorityMask;
	}

	BackendWin32::BackendWin32(const DWORD processId)
		: WindowsProcessBase(processId) {
	}
#pragma endregion

#pragma region Implementation: WindowsProcessNt
	std::wstring BackendNt::QueryObjectNameNt(HANDLE h) noexcept
	{
		if (!h) return L"";
		HANDLE dupHandle = nullptr;

		if (!DuplicateHandle(
			OpenProcess(PROCESS_DUP_HANDLE, FALSE, m_processId),
			h,
			GetCurrentProcess(),
			&dupHandle,
			0,
			FALSE,
			DUPLICATE_SAME_ACCESS))
		{
			return L"";
		}

		std::wstring result;
		ULONG size = 0;

		// First call to query size
		NtQueryObject(dupHandle, ObjectNameInformation, nullptr, 0, &size);
		if (size)
		{
			auto* nameBuffer = reinterpret_cast<POBJECT_NAME_INFORMATION>(new BYTE[size]);
			if (NT_SUCCESS(NtQueryObject(dupHandle, ObjectNameInformation, nameBuffer, size, nullptr)))
			{
				if (nameBuffer->Name.Buffer && nameBuffer->Name.Length > 0)
				{
					// Copy to std::wstring
					result.assign(nameBuffer->Name.Buffer, nameBuffer->Name.Length / sizeof(WCHAR));
				}
			}
			delete[] nameBuffer;
		}

		CloseHandle(dupHandle);
		return result;
	}

	std::wstring BackendNt::QueryObjectTypeNameNt(HANDLE h) noexcept
	{
		if (!h) return L"";

		HANDLE dupHandle = nullptr;
		if (!DuplicateHandle(
			OpenProcess(PROCESS_DUP_HANDLE, FALSE, m_processId),
			h,
			GetCurrentProcess(),
			&dupHandle,
			0,
			FALSE,
			DUPLICATE_SAME_ACCESS))
		{
			return L"";
		}

		std::wstring result;
		ULONG size = 0;

		// First call to query size
		NtQueryObject(dupHandle, ObjectTypeInformation, nullptr, 0, &size);
		if (size)
		{
			auto* typeInfo = reinterpret_cast<POBJECT_TYPE_INFORMATION>(new BYTE[size]);
			if (NT_SUCCESS(NtQueryObject(dupHandle, ObjectTypeInformation, typeInfo, size, nullptr)))
			{
				// Assign to result, not a local variable
				if (typeInfo->TypeName.Buffer && typeInfo->TypeName.Length > 0)
					result.assign(typeInfo->TypeName.Buffer, typeInfo->TypeName.Length / sizeof(WCHAR));
			}
			delete[] typeInfo;
		}

		CloseHandle(dupHandle);
		return result;
	}

	void BackendNt::QueryModules(HANDLE hProc) noexcept
	{
		// read remote PEB
		PEB peb{ ReadVirtualMemoryNt<PEB>(hProc, m_pebAddress) };
		if (!peb.Ldr) return;

		// read remote PEB_LDR_DATA
		uintptr_t ldrAddr{ reinterpret_cast<uintptr_t>(peb.Ldr) };
		PEB_LDR_DATA ldr{ ReadVirtualMemoryNt<PEB_LDR_DATA>(hProc, ldrAddr) };
		if (!ldr.InLoadOrderModuleList.Flink) return;

		// remote list head
		uintptr_t listHead{ ldrAddr + offsetof(PEB_LDR_DATA, InLoadOrderModuleList) };

		// first remote link
		uintptr_t currentLink{ reinterpret_cast<uintptr_t>(ldr.InLoadOrderModuleList.Flink) };

		while (currentLink && currentLink != listHead)
		{
			// first remote module = fLink - ILOL offset
			uintptr_t entryAddr{ currentLink - offsetof(LDR_DATA_TABLE_ENTRY, InLoadOrderLinks) };
			LDR_DATA_TABLE_ENTRY entry{ ReadVirtualMemoryNt<LDR_DATA_TABLE_ENTRY>(hProc, entryAddr) };

			ModuleEntry mEntry{};
			mEntry.baseAddress = reinterpret_cast<uintptr_t>(entry.DllBase);
			mEntry.moduleBaseSize = entry.SizeOfImage;
			mEntry.entryPoint = entry.EntryPoint;
			mEntry.globalLoadCount = entry.ObsoleteLoadCount;
			mEntry.processLoadCount = 0;
			mEntry.processId = m_processId;
			mEntry.moduleName = ReadRemoteUnicodeStringNt(hProc, entry.BaseDllName);
			mEntry.modulePath = ReadRemoteUnicodeStringNt(hProc, entry.FullDllName);
			m_modules.push_back(std::move(mEntry));

			// advance
			currentLink = reinterpret_cast<uintptr_t>(entry.InLoadOrderLinks.Flink);
		}
	}

	void BackendNt::QueryHandles() noexcept
	{
		DWORD requiredBufferSize{ GetQSIBuffferSizeNt(
			SystemHandleInformation) + 0x1000 };
		BYTE* hInfoBuffer = new BYTE[requiredBufferSize];
		NTSTATUS ntStatus{ NtQuerySystemInformation(
				SystemHandleInformation,
				hInfoBuffer,
				requiredBufferSize,
				nullptr) };

		if (!NT_SUCCESS(ntStatus))
		{
			delete[] hInfoBuffer;
			return;
		}

		PSYSTEM_HANDLE_INFORMATION pHandles = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION>(hInfoBuffer);

		// Handle parsing
		for (ULONG i = 0; i < pHandles->NumberOfHandles; ++i)
		{
			const SYSTEM_HANDLE_TABLE_ENTRY_INFO& sHandleInfo = pHandles->Handles[i];
			if (static_cast<uintptr_t>(sHandleInfo.UniqueProcessId) != static_cast<uintptr_t>(m_processId))
				continue;

			HandleEntry handle{};
			handle.handle = reinterpret_cast<HANDLE>(sHandleInfo.HandleValue);
			handle.typeName = QueryObjectTypeName(handle.handle);
			handle.objectName = QueryObjectName(handle.handle);
			handle.attributes = sHandleInfo.HandleAttributes;
			handle.grantedAccess = sHandleInfo.GrantedAccess;
			m_handles.push_back(handle);
		}

		delete[] hInfoBuffer;
	}

	void BackendNt::QueryExtendedProcessInfoNt(HANDLE hProc, BackendNt& proc)
	{
		PROCESS_EXTENDED_BASIC_INFORMATION pExtendedInfo{};
		NTSTATUS ntProcExtendedInfoStatus = NtQueryInformationProcess(
			hProc,
			ProcessBasicInformation,
			&pExtendedInfo,
			sizeof(PROCESS_EXTENDED_BASIC_INFORMATION),
			nullptr);
		if (!NT_SUCCESS(ntProcExtendedInfoStatus)) return;

		proc.m_pebAddress = reinterpret_cast<uintptr_t>(pExtendedInfo.BasicInfo.PebBaseAddress);
		proc.m_moduleBaseAddress = reinterpret_cast<uintptr_t>(
			proc.ReadVirtualMemoryNt<PEB>(hProc, proc.m_pebAddress).ImageBaseAddress);
		proc.m_isWow64 = pExtendedInfo.u.s.IsWow64Process;
		proc.m_isProtectedProcess = pExtendedInfo.u.s.IsProtectedProcess;
		proc.m_isBackgroundProcess = pExtendedInfo.u.s.IsBackground;
		proc.m_isSecureProcess = pExtendedInfo.u.s.IsSecureProcess;
		proc.m_isSubsystemProcess = pExtendedInfo.u.s.IsSubsystemProcess;
	}

	void BackendNt::QueryImageFilePathNt(HANDLE hProc, BackendNt& proc)
	{
		BYTE imageFileNameBuffer[512] = {};
		NTSTATUS ntImageFileNameStatus = NtQueryInformationProcess(
			hProc,
			ProcessImageFileName,
			imageFileNameBuffer,
			sizeof(imageFileNameBuffer),
			nullptr);
		if (!NT_SUCCESS(ntImageFileNameStatus)) return;

		PUNICODE_STRING imageFileName = reinterpret_cast<PUNICODE_STRING>(imageFileNameBuffer);
		if (imageFileName->Buffer && imageFileName->Length)
		{
			proc.m_imageFilePath.assign(
				imageFileName->Buffer,
				imageFileName->Length / sizeof(wchar_t));
		}
	}

	void BackendNt::QueryPriorityClassNt(HANDLE hProc, BackendNt& proc)
	{
		PROCESS_PRIORITY_CLASS pPriorityClass{};
		NTSTATUS ntProcPriorityClassStatus = NtQueryInformationProcess(
			hProc,
			ProcessPriorityClass,
			&pPriorityClass,
			sizeof(PROCESS_PRIORITY_CLASS),
			nullptr);
		if (!NT_SUCCESS(ntProcPriorityClassStatus)) return;

		switch (pPriorityClass.PriorityClass)
		{
		case 0U: proc.m_priorityClass = PriorityClass::Undefined;
			break;
		case 1U: proc.m_priorityClass = PriorityClass::Idle;
			break;
		case 2U: proc.m_priorityClass = PriorityClass::Normal;
			break;
		case 3U: proc.m_priorityClass = PriorityClass::High;
			break;
		case 4U: proc.m_priorityClass = PriorityClass::Realtime;
			break;
		case 5U: proc.m_priorityClass = PriorityClass::BelowNormal;
			break;
		case 6U: proc.m_priorityClass = PriorityClass::AboveNormal;
			break;
		default: proc.m_priorityClass = PriorityClass::Undefined;
			break;
		}
	}

	void BackendNt::QueryModuleBaseAddressNt(HANDLE hProc, BackendNt& proc)
	{
		// Implement PEB walker
		return;
	}

	void BackendNt::QueryArchitectureNt(HANDLE hProc, BackendNt& proc)
	{
		PVOID wow64Info = nullptr;
		NTSTATUS ntWow64InfoStatus = NtQueryInformationProcess(
			hProc,
			ProcessWow64Information,
			&wow64Info,
			sizeof(PVOID),
			nullptr);
		if (!NT_SUCCESS(ntWow64InfoStatus)) return;

		// nullptr = native process, Wow64 pointer = 32-bit process
		proc.m_architectureType = (wow64Info != nullptr) ? ArchitectureType::x86 : ArchitectureType::x64;
	}

	void BackendNt::QueryVisibleWindowNt(HANDLE hProc, BackendNt& proc)
	{

	}

	std::vector<BackendNt> BackendNt::GetProcessListNt()
	{
		std::vector<BackendNt> result;

		// Query system process information
		const DWORD requiredSysProcInfoBufferSize{ GetQSIBuffferSizeNt(SystemProcessInformation) };
		BYTE* sysProcInfoBuffer = new BYTE[requiredSysProcInfoBufferSize];
		NTSTATUS ntSysStatus{ NtQuerySystemInformation(
			SystemProcessInformation,
			sysProcInfoBuffer,
			requiredSysProcInfoBufferSize,
			nullptr) };

		if (!NT_SUCCESS(ntSysStatus))
		{
			delete[] sysProcInfoBuffer;
			return result;
		}

		PSYSTEM_PROCESS_INFORMATION procInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(sysProcInfoBuffer);
		while (procInfo)
		{
			DWORD processId = static_cast<DWORD>(reinterpret_cast<uintptr_t>(procInfo->UniqueProcessId));
			DWORD parentProcessId = static_cast<DWORD>(reinterpret_cast<uintptr_t>(procInfo->InheritedFromUniqueProcessId));
			BackendNt wProcNt{ processId };
			wProcNt.m_name = (procInfo->ImageName.Buffer) ? procInfo->ImageName.Buffer : L"";
			wProcNt.m_parentProcessId = parentProcessId;

			HANDLE hProc{ OpenProcessHandleNt(processId, PROCESS_ALL_ACCESS) };
			if (!IsValidHandle(hProc)) hProc = OpenProcessHandleNt(processId, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);
			if (!IsValidHandle(hProc)) hProc = OpenProcessHandleNt(processId, PROCESS_QUERY_LIMITED_INFORMATION);

			QueryExtendedProcessInfoNt(hProc, wProcNt);
			QueryImageFilePathNt(hProc, wProcNt);
			QueryPriorityClassNt(hProc, wProcNt);
			QueryArchitectureNt(hProc, wProcNt);
			QueryModuleBaseAddressNt(hProc, wProcNt);
			wProcNt.QueryModules(hProc);

			// Threads
			for (ULONG i = 0; i < procInfo->NumberOfThreads; ++i)
			{
				ThreadEntry threadEntry{};
				const SYSTEM_THREAD_INFORMATION& sThreadInfo = procInfo->Threads[i];

				threadEntry.size = sizeof(SYSTEM_THREAD_INFORMATION);
				threadEntry.threadId = static_cast<DWORD>(
					reinterpret_cast<uintptr_t>(sThreadInfo.ClientId.UniqueThread));
				threadEntry.ownerProcessId = processId;
				threadEntry.basePriority = sThreadInfo.BasePriority;
				threadEntry.startAddress = sThreadInfo.StartAddress;
				threadEntry.threadState = sThreadInfo.ThreadState;
				wProcNt.m_threads.push_back(threadEntry);
			}
			result.push_back(wProcNt);
			NtClose(hProc);

			// Advance to next process (ALWAYS)
			if (procInfo->NextEntryOffset)
			{
				procInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(
					reinterpret_cast<BYTE*>(procInfo) + procInfo->NextEntryOffset);
			}
			else break;
		}

		delete[] sysProcInfoBuffer;
		return result;
	}

	HANDLE BackendNt::OpenProcessHandleNt(const DWORD processId, const ACCESS_MASK accessMask)
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

	DWORD BackendNt::GetQSIBufferSizeNt(const SYSTEM_INFORMATION_CLASS sInfoClass)
	{
		DWORD requiredBufferSize{};
		BYTE buffer[0x20];

		NTSTATUS ntStatus{ NtQuerySystemInformation(
			sInfoClass,
			buffer,
			sizeof(buffer),
			&requiredBufferSize) };

		return requiredBufferSize;
	}

	std::wstring BackendNt::ReadRemoteUnicodeStringNt(HANDLE hProc, const UNICODE_STRING& us)
	{
		if (!us.Buffer || !us.Length) return {};
		std::wstring s(us.Length / sizeof(wchar_t), L'\0');

		NtReadVirtualMemory(
			hProc,
			reinterpret_cast<PVOID>(us.Buffer),
			s.data(),
			us.Length,
			nullptr);

		return s;
	}

	BackendNt::BackendNt(const DWORD processId)
		: WindowsProcessBase(processId) {
	}
#pragma endregion
}