#include "process.hpp"
#include <TlHelp32.h>
#include <Psapi.h>
#pragma comment(lib, "ntdll.lib")

namespace corvus::process
{
#pragma region Process
	explicit WindowsProcess::WindowsProcess(const DWORD processId)
		: m_process{}
	{
		if (!corvus::process::WindowsBackend::IsValidProcessId(processId)) throw std::invalid_argument("Invalid PID");
		else m_process.processId = processId;

		m_processHandle = corvus::process::WindowsBackend::OpenProcessHandleNt(processId, PROCESS_ALL_ACCESS);
		if (!corvus::process::WindowsBackend::IsValidHandle(m_processHandle))
			m_processHandle = corvus::process::WindowsBackend::OpenProcessHandleNt(processId, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);
		if (!corvus::process::WindowsBackend::IsValidHandle(m_processHandle))
			m_processHandle = corvus::process::WindowsBackend::OpenProcessHandleNt(processId, PROCESS_QUERY_LIMITED_INFORMATION);
		if (!corvus::process::WindowsBackend::IsValidHandle(m_processHandle))
			m_processHandle = INVALID_HANDLE_VALUE;
	};
	WindowsProcess::~WindowsProcess()
	{
		if (corvus::process::WindowsBackend::IsValidHandle(m_processHandle))
		{
			NtClose(m_processHandle);
			m_processHandle = INVALID_HANDLE_VALUE;
		}
	};

	const std::wstring& WindowsProcess::GetProcessEntryName() const noexcept { return m_process.name; }
	const std::string& WindowsProcess::GetProcessEntryNameA() const noexcept { return ToString(m_process.name); }
	const std::wstring& WindowsProcess::GetProcessEntryImageFilePath() const noexcept { return m_process.imageFilePath; }
	const std::string& WindowsProcess::GetProcessEntryImageFilePathA() const noexcept { return ToString(m_process.imageFilePath); }
	const std::vector<ModuleEntry>& WindowsProcess::GetModules() const noexcept { return m_modules; }
	const std::vector<ThreadEntry>& WindowsProcess::GetThreads() const noexcept { return m_threads; }
	const std::vector<HandleEntry>& WindowsProcess::GetHandles() const noexcept { return m_handles; }
	uintptr_t WindowsProcess::GetModuleBaseAddress() const noexcept { return m_process.moduleBaseAddress; }
	uintptr_t WindowsProcess::GetPEBAddress() const noexcept { return m_process.pebAddress; }
	DWORD WindowsProcess::GetProcessId() const noexcept { return m_process.processId; }
	HANDLE WindowsProcess::GetProcessHandle() const noexcept { return m_processHandle; }
	const std::string& WindowsProcess::GetProcessIdA() const noexcept { return ToString(m_process.processId); }
	DWORD WindowsProcess::GetParentProcessId() const noexcept { return m_process.parentProcessId; }
	PriorityClass WindowsProcess::GetPriorityClass() const noexcept { return m_process.priorityClass; }
	const char* WindowsProcess::GetPriorityClassA() const noexcept { return ToString(m_process.priorityClass); }
	BOOL WindowsProcess::IsWow64() const noexcept { return m_process.isWow64; }
	BOOL WindowsProcess::IsProtectedProcess() const noexcept { return m_process.isProtectedProcess; }
	BOOL WindowsProcess::IsBackgroundProcess() const noexcept { return m_process.isBackgroundProcess; }
	BOOL WindowsProcess::IsSecureProcess() const noexcept { return m_process.isSecureProcess; }
	BOOL WindowsProcess::IsSubsystemProcess() const noexcept { return m_process.isSubsystemProcess; }
	BOOL WindowsProcess::HasVisibleWindow() const noexcept { return m_process.hasVisibleWindow; }
	ArchitectureType WindowsProcess::GetArchitectureType() const noexcept { return m_process.architectureType; }
	const char* WindowsProcess::GetArchitectureTypeA() const noexcept { return ToString(m_process.architectureType); }

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

#pragma region Backend valid
	bool WindowsBackend::IsValidProcessId(const DWORD processId) noexcept { return processId % 4 == 0; }
	bool WindowsBackend::IsValidAddress(const DWORD address) noexcept { return address != ERROR_INVALID_ADDRESS; }
	bool WindowsBackend::IsValidHandle(const HANDLE handle) noexcept
	{
		return (handle != nullptr &&
			handle != reinterpret_cast<HANDLE>(-1) &&
			handle != INVALID_HANDLE_VALUE);
	}
#pragma endregion

#pragma region Backend
#pragma region Queries
	PROCESS_EXTENDED_BASIC_INFORMATION WindowsBackend::QueryExtendedProcessInfoNt(HANDLE hProcess)
	{
		PROCESS_EXTENDED_BASIC_INFORMATION pExtendedInfo{};
		NTSTATUS ntProcExtendedInfoStatus = NtQueryInformationProcess(
			hProcess,
			ProcessBasicInformation,
			&pExtendedInfo,
			sizeof(PROCESS_EXTENDED_BASIC_INFORMATION),
			nullptr);
		if (!NT_SUCCESS(ntProcExtendedInfoStatus)) return;
		else return pExtendedInfo;
	}

	std::wstring WindowsBackend::QueryProcessName32(DWORD processId)
	{
		// CreateToolhelp32Snapshot ignores th32ProcessId when using TH32CS_SNAPPROCESS
		HANDLE hProcessSnapshot{ CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
		if (!IsValidHandle(hProcessSnapshot)) return L"";

		PROCESSENTRY32W pEntry{};
		pEntry.dwSize = sizeof(pEntry);
		if (!Process32FirstW(hProcessSnapshot, &pEntry)) return L"";

		do
		{
			if (pEntry.th32ProcessID == processId)
			{
				CloseHandle(hProcessSnapshot);
				return pEntry.szExeFile;
			}
		} while (Process32NextW(hProcessSnapshot, &pEntry));

		CloseHandle(hProcessSnapshot);
		return L"";
	}

	std::wstring WindowsBackend::QueryImageFilePath32(HANDLE hProcess)
	{
		std::wstring iFilePathBuffer{};
		iFilePathBuffer.resize(32768);
		DWORD size = static_cast<DWORD>(iFilePathBuffer.size());

		if (!QueryFullProcessImageNameW(hProcess, 0, iFilePathBuffer.data(), &size)) return L"";
		iFilePathBuffer.resize(size);

		return iFilePathBuffer;
	}

	std::wstring WindowsBackend::QueryImageFilePathNt(HANDLE hProcess)
	{
		BYTE imageFileNameBuffer[512]{};
		NTSTATUS ntImageFileNameStatus{ NtQueryInformationProcess(
			hProcess,
			ProcessImageFileName,
			imageFileNameBuffer,
			sizeof(imageFileNameBuffer),
			nullptr) };
		if (!NT_SUCCESS(ntImageFileNameStatus)) return L"";

		PUNICODE_STRING imageFileName = reinterpret_cast<PUNICODE_STRING>(imageFileNameBuffer);
		std::wstring result{};
		if (imageFileName->Buffer && imageFileName->Length)
		{
			result.assign(
				imageFileName->Buffer,
				imageFileName->Length / sizeof(wchar_t));
		}
		return result;
	}

	std::vector<ModuleEntry> WindowsBackend::QueryModules32(HANDLE hProcess, DWORD processId)
	{
		if (!IsValidHandle(hProcess)) return {};
		HANDLE hModuleSnapshot{
			CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId) };
		if (!IsValidHandle(hModuleSnapshot)) return {};

		MODULEINFO mInfoBuffer{};
		MODULEENTRY32W mEntry{};
		mEntry.dwSize = sizeof(MODULEENTRY32W);
		if (!Module32FirstW(hModuleSnapshot, &mEntry))
		{
			CloseHandle(hModuleSnapshot);
			return {};
		}

		std::vector<ModuleEntry> modules{};
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
			module.structureSize = mEntry.dwSize;
			module.baseAddress = reinterpret_cast<uintptr_t>(mEntry.modBaseAddr);
			module.moduleBaseSize = mEntry.modBaseSize;
			module.entryPoint = mInfoBuffer.EntryPoint;
			module.processId = mEntry.th32ProcessID;
			module.globalLoadCount = mEntry.GlblcntUsage;
			module.processLoadCount = mEntry.ProccntUsage;
			modules.push_back(module);

		} while (Module32NextW(hModuleSnapshot, &mEntry));
		CloseHandle(hModuleSnapshot);
		return modules;
	}

	std::vector<ModuleEntry> WindowsBackend::QueryModulesNt(HANDLE hProcess, PROCESS_EXTENDED_BASIC_INFORMATION& pInfo)
	{
		uintptr_t pebAddress{ reinterpret_cast<uintptr_t>(pInfo.BasicInfo.PebBaseAddress) };
		if (!IsValidAddress(pebAddress)) return {};

		PEB peb{};
		if (!NT_SUCCESS(ReadVirtualMemoryNt<PEB>(hProcess, pebAddress, peb))) return {};
		if (!peb.Ldr) return {};

		uintptr_t ldrAddr{ reinterpret_cast<uintptr_t>(peb.Ldr) };
		if (!IsValidAddress(ldrAddr)) return {};

		PEB_LDR_DATA ldr{};
		if (!NT_SUCCESS(ReadVirtualMemoryNt<PEB_LDR_DATA>(hProcess, ldrAddr, ldr))) return {};
		if (!ldr.InLoadOrderModuleList.Flink) return {};

		uintptr_t listHead{ ldrAddr + offsetof(PEB_LDR_DATA, InLoadOrderModuleList) };
		if (!IsValidAddress(listHead)) return {};

		uintptr_t currentLink{ reinterpret_cast<uintptr_t>(ldr.InLoadOrderModuleList.Flink) };
		if (!IsValidAddress(currentLink)) return {};

		std::vector<ModuleEntry> modules{};
		size_t sanityCounter = 0;
		while (currentLink && currentLink != listHead)
		{
			if (++sanityCounter > 1024)
				break;

			// first remote module = fLink - ILOL offset
			uintptr_t entryAddr{ currentLink - offsetof(LDR_DATA_TABLE_ENTRY, InLoadOrderLinks) };
			LDR_DATA_TABLE_ENTRY entry{};
			if (!NT_SUCCESS(ReadVirtualMemoryNt<LDR_DATA_TABLE_ENTRY>(hProcess, entryAddr, entry)))
				break;

			ModuleEntry mEntry{};
			mEntry.baseAddress = reinterpret_cast<uintptr_t>(entry.DllBase);
			mEntry.moduleBaseSize = entry.SizeOfImage;
			mEntry.entryPoint = entry.EntryPoint;
			mEntry.globalLoadCount = entry.ObsoleteLoadCount;
			mEntry.processLoadCount = 0;
			mEntry.processId = reinterpret_cast<DWORD>(pInfo.BasicInfo.UniqueProcessId);
			mEntry.moduleName = ReadRemoteUnicodeStringNt(hProcess, entry.BaseDllName);
			mEntry.modulePath = ReadRemoteUnicodeStringNt(hProcess, entry.FullDllName);
			modules.push_back(std::move(mEntry));

			uintptr_t next = reinterpret_cast<uintptr_t>(entry.InLoadOrderLinks.Flink);
			if (!IsValidAddress(next) || next == currentLink) break;
			else currentLink = next;
		};
		return modules;
	};

	std::vector<ThreadEntry> WindowsBackend::QueryThreads32(HANDLE hProcess, DWORD processId)
	{
		if (!IsValidHandle(hProcess)) return {};
		HANDLE hThreadSnapshot{
			CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, processId) };
		if (!IsValidHandle(hThreadSnapshot)) return {};

		THREADENTRY32 tEntry{};
		tEntry.dwSize = sizeof(THREADENTRY32);
		if (!Thread32First(hThreadSnapshot, &tEntry))
		{
			CloseHandle(hThreadSnapshot);
			return {};
		}

		std::vector<ThreadEntry> threads{};
		do
		{
			if (tEntry.th32OwnerProcessID != processId) continue;

			ThreadEntry thread{};
			thread.structureSize = tEntry.dwSize;
			thread.threadId = tEntry.th32ThreadID;
			thread.ownerProcessId = tEntry.th32OwnerProcessID;
			thread.basePriority = tEntry.tpBasePri; //KeQueryPriorityThread
			threads.push_back(thread);

		} while (Thread32Next(hThreadSnapshot, &tEntry));
		CloseHandle(hThreadSnapshot);
		return threads;
	}

	std::vector<HandleEntry> WindowsBackend::QueryHandles32(HANDLE hProcess, DWORD processId)
	{
		if (!IsValidHandle(hProcess)) return {};
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

		std::vector<HandleEntry> handles{};
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
			if (walkStatus == ERROR_NO_MORE_ITEMS) break;
			if (walkStatus != ERROR_SUCCESS) break;

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
				handle.targetProcessId = 0; // Other cases don't have a OwnerProcessId
				break;
			}

			handles.push_back(handle);
		}

		PssWalkMarkerFree(hWalkMarker);
		PssFreeSnapshot(GetCurrentProcess(), pssSnapshot);
		return handles;
	}

	std::vector<HandleEntry> WindowsBackend::QueryHandlesNt(DWORD processId)
	{
		DWORD requiredBufferSize{ GetQSIBufferSizeNt(
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
			return {};
		}

		PSYSTEM_HANDLE_INFORMATION pHandles = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION>(hInfoBuffer);

		std::vector<HandleEntry> handles{};
		for (ULONG i = 0; i < pHandles->NumberOfHandles; ++i)
		{
			const SYSTEM_HANDLE_TABLE_ENTRY_INFO& sHandleInfo = pHandles->Handles[i];
			if (static_cast<uintptr_t>(sHandleInfo.UniqueProcessId) != static_cast<uintptr_t>(processId))
				continue;

			HandleEntry handle{};
			handle.handle = reinterpret_cast<HANDLE>(sHandleInfo.HandleValue);
			handle.typeName = QueryObjectTypeNameNt(handle.handle, sHandleInfo.UniqueProcessId);
			handle.objectName = QueryObjectNameNt(handle.handle, sHandleInfo.UniqueProcessId);
			handle.attributes = sHandleInfo.HandleAttributes;
			handle.grantedAccess = sHandleInfo.GrantedAccess;
			handles.push_back(handle);
		}

		delete[] hInfoBuffer;
		return handles;
	}

	uintptr_t WindowsBackend::QueryModuleBaseAddress32(DWORD processId, const std::wstring& processName)
	{
		MODULEENTRY32W mEntry{};
		mEntry.dwSize = sizeof(MODULEENTRY32W);
		HANDLE hModuleSnapshot{
			CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId) };

		if (!IsValidHandle(hModuleSnapshot)) return 0;
		if (!Module32FirstW(hModuleSnapshot, &mEntry))
		{
			CloseHandle(hModuleSnapshot);
			return 0;
		}

		do
		{
			if (_wcsicmp(mEntry.szModule, processName.c_str()) == 0)
			{
				CloseHandle(hModuleSnapshot);
				return reinterpret_cast<uintptr_t>(mEntry.modBaseAddr);
			}
		} while (Module32Next(hModuleSnapshot, &mEntry));

		CloseHandle(hModuleSnapshot);
		return 0;
	}

	PriorityClass WindowsBackend::QueryPriorityClass32(HANDLE hProcess)
	{
		return static_cast<PriorityClass>(::GetPriorityClass(hProcess));
	}

	PriorityClass WindowsBackend::QueryPriorityClassNt(HANDLE hProcess)
	{
		PROCESS_PRIORITY_CLASS pPriorityClass{};
		NTSTATUS ntProcPriorityClassStatus{ NtQueryInformationProcess(
			hProcess,
			ProcessPriorityClass,
			&pPriorityClass,
			sizeof(PROCESS_PRIORITY_CLASS),
			nullptr) };
		if (!NT_SUCCESS(ntProcPriorityClassStatus)) return PriorityClass::Undefined;

		switch (pPriorityClass.PriorityClass)
		{
		case 0U: return PriorityClass::Undefined;
		case 1U: return PriorityClass::Idle;
		case 2U: return PriorityClass::Normal;
		case 3U: return PriorityClass::High;
		case 4U: return PriorityClass::Realtime;
		case 5U: return PriorityClass::BelowNormal;
		case 6U: return PriorityClass::AboveNormal;
		default: return PriorityClass::Undefined;
		}
	}

	bool WindowsBackend::QueryVisibleWindow32(DWORD processId)
	{
		for (HWND hwnd = GetTopWindow(nullptr); hwnd; hwnd = GetNextWindow(hwnd, GW_HWNDNEXT))
		{
			DWORD windowThreadProcessId{};
			GetWindowThreadProcessId(hwnd, &windowThreadProcessId);
			if (windowThreadProcessId == processId && IsWindowVisible(hwnd)) return true;
		}
		return false;
	}

	ArchitectureType WindowsBackend::QueryArchitecture32(HANDLE hProcess, bool& isWow64)
	{
		if (!IsValidHandle(hProcess)) return {};

		// processMachine = type of WoW process, nativeMachine = native architecture of host system
		USHORT processMachine{ IMAGE_FILE_MACHINE_UNKNOWN };
		USHORT nativeMachine{ IMAGE_FILE_MACHINE_UNKNOWN };
		if (!IsWow64Process2(hProcess, &processMachine, &nativeMachine))
		{
			isWow64 = FALSE;
			return ArchitectureType::Unknown;
		}

		// emulation check
		isWow64 = (processMachine != IMAGE_FILE_MACHINE_UNKNOWN);

		// determine effective architecture
		const USHORT machine{ isWow64 ? processMachine : nativeMachine };
		switch (machine)
		{
		case IMAGE_FILE_MACHINE_UNKNOWN: return ArchitectureType::Unknown;
		case IMAGE_FILE_MACHINE_I386: return ArchitectureType::x86;
		case IMAGE_FILE_MACHINE_AMD64: return ArchitectureType::x64;
		default: return ArchitectureType::Unknown;
		}
	}

	ArchitectureType WindowsBackend::QueryArchitectureNt(HANDLE hProcess)
	{
		PVOID wow64Info{};
		NTSTATUS ntWow64InfoStatus{ NtQueryInformationProcess(
			hProcess,
			ProcessWow64Information,
			&wow64Info,
			sizeof(PVOID),
			nullptr) };
		if (!NT_SUCCESS(ntWow64InfoStatus)) return;

		// nullptr = native process, Wow64 pointer = 32-bit process
		return (wow64Info != nullptr) ? ArchitectureType::x86 : ArchitectureType::x64;
	}

	bool WindowsBackend::QuerySeDebugPrivilege32(HANDLE hProcess)
	{
		if (!IsValidHandle(hProcess)) return false;
		HANDLE hToken{};
		if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) return false;

		DWORD size{};
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

		bool enabled{ false };
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

	int WindowsBackend::QueryThreadPriority32(HANDLE hThread)
	{
		return GetThreadPriority(hThread);
	}

	std::wstring WindowsBackend::QueryObjectNameNt(HANDLE hObject, DWORD processId)
	{
		if (!IsValidHandle(hObject)) return L"";
		HANDLE localProcessHandle{ OpenProcessHandleNt(processId, PROCESS_DUP_HANDLE) };
		if (!IsValidHandle(localProcessHandle)) return L"";

		HANDLE dupHandle{};
		if (!DuplicateHandle(
			localProcessHandle,
			hObject,
			GetCurrentProcess(),
			&dupHandle,
			0,
			FALSE,
			DUPLICATE_SAME_ACCESS))
		{
			NtClose(localProcessHandle);
			return L"";
		}

		ULONG size{};
		NtQueryObject(dupHandle, ObjectNameInformation, nullptr, 0, &size);
		if (!size)
		{
			NtClose(localProcessHandle);
			NtClose(dupHandle);
			return L"";
		}

		POBJECT_NAME_INFORMATION nameBuffer{
			reinterpret_cast<POBJECT_NAME_INFORMATION>(new BYTE[size]) };
		std::wstring result{};
		if (NT_SUCCESS(NtQueryObject(dupHandle, ObjectNameInformation, nameBuffer, size, nullptr)))
		{
			if (nameBuffer->Name.Buffer && nameBuffer->Name.Length > 0)
			{
				result.assign(nameBuffer->Name.Buffer, nameBuffer->Name.Length / sizeof(WCHAR));
			}
		}

		delete[] nameBuffer;
		NtClose(localProcessHandle);
		NtClose(dupHandle);
		return result;
	}

	std::wstring WindowsBackend::QueryObjectTypeNameNt(HANDLE hObject, DWORD processId)
	{
		if (!IsValidHandle(hObject)) return L"";
		HANDLE localProcessHandle{ OpenProcessHandleNt(processId, PROCESS_DUP_HANDLE) };
		if (!IsValidHandle(localProcessHandle)) return L"";

		HANDLE dupHandle{};
		if (!DuplicateHandle(
			localProcessHandle,
			hObject,
			GetCurrentProcess(),
			&dupHandle,
			0,
			FALSE,
			DUPLICATE_SAME_ACCESS))
		{
			NtClose(localProcessHandle);
			return L"";
		}

		ULONG size{};
		NtQueryObject(dupHandle, ObjectTypeInformation, nullptr, 0, &size);
		if (!size)
		{
			NtClose(localProcessHandle);
			NtClose(dupHandle);
			return L"";
		}

		POBJECT_TYPE_INFORMATION typeInfo{
			reinterpret_cast<POBJECT_TYPE_INFORMATION>(new BYTE[size]) };
		std::wstring result{};
		if (NT_SUCCESS(NtQueryObject(dupHandle, ObjectTypeInformation, typeInfo, size, nullptr)))
		{
			if (typeInfo->TypeName.Buffer && typeInfo->TypeName.Length > 0)
				result.assign(typeInfo->TypeName.Buffer, typeInfo->TypeName.Length / sizeof(WCHAR));
		}

		delete[] typeInfo;
		CloseHandle(localProcessHandle);
		CloseHandle(dupHandle);
		return result;
	}
#pragma endregion

#pragma region Operations
	BOOL WindowsBackend::EnableSeDebugPrivilege32()
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

	BOOL WindowsBackend::EnableSeDebugPrivilege32(const DWORD processId)
	{
		HANDLE hProc{ OpenProcessHandle32(processId, PROCESS_ALL_ACCESS) };
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

	BOOL WindowsBackend::SetThreadPriority32(int priorityMask)
	{
		return SetPriorityClass(GetCurrentProcess(), priorityMask);
	}

	HANDLE WindowsBackend::OpenProcessHandle32(const DWORD processId, const ACCESS_MASK accessMask)
	{
		return OpenProcess(accessMask, FALSE, processId);
	}

	HANDLE WindowsBackend::OpenProcessHandleNt(const DWORD processId, const ACCESS_MASK accessMask)
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

	BOOL  WindowsBackend::SuspendThread32(const DWORD threadId)
	{
		HANDLE hThread{ OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadId) };
		if (!hThread) return FALSE;
		SuspendThread(hThread);
		CloseHandle(hThread);
		return TRUE;
	}

	BOOL WindowsBackend::ResumeThread32(const DWORD threadId)
	{
		HANDLE hThread{ OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadId) };
		if (!hThread) return FALSE;
		ResumeThread(hThread);
		CloseHandle(hThread);
		return TRUE;
	}

	void WindowsBackend::PatchExecutionExt32(HANDLE processHandle, DWORD destination, BYTE* value, unsigned int size)
	{
		// Changes the protection on a region of committed pages in the virtual address space of a specified process.
		// https://learn.microsoft.com/en-us/windows/win32/Memory/memory-protection-constants

		DWORD oldPageProtection;
		VirtualProtectEx(processHandle, (void*)destination, size, PAGE_EXECUTE_READWRITE, &oldPageProtection);
		WriteProcessMemory(processHandle, (void*)destination, value, size, nullptr);
	}

	void WindowsBackend::PatchExecutionInt32(DWORD destination, BYTE* value, unsigned int size)
	{
		DWORD oldPageProtection;
		VirtualProtect((void*)destination, size, PAGE_EXECUTE_READWRITE, &oldPageProtection);
		memcpy((void*)destination, value, size);
		VirtualProtect((void*)destination, size, oldPageProtection, &oldPageProtection);
	}

	void WindowsBackend::NopExecutionExt32(HANDLE processHandle, DWORD destination, unsigned int size)
	{
		// Filling an array with x86 NOP instructions (0x90)
		BYTE* noOperationArray = new BYTE[size];
		memset(noOperationArray, 0x90, size);

		PatchExecutionExt32(processHandle, destination, noOperationArray, size);
		delete[] noOperationArray;
	}

	void WindowsBackend::NopExecutionInt32(DWORD destination, unsigned int size)
	{
		DWORD oldPageProtection;
		VirtualProtect((void*)destination, size, PAGE_EXECUTE_READWRITE, &oldPageProtection);
		memset((void*)destination, 0x90, size);
		VirtualProtect((void*)destination, size, oldPageProtection, &oldPageProtection);
	}

	DWORD WindowsBackend::FindDMAAddyExt32(HANDLE processHandle, DWORD ptr, std::vector<DWORD> offsets)
	{
		DWORD addr{ ptr };
		for (unsigned int i = 0; i < offsets.size(); ++i)
		{
			ReadProcessMemory(processHandle, (void*)addr, &addr, sizeof(addr), nullptr);
			addr += offsets[i];
		}
		return addr;
	}

	DWORD WindowsBackend::FindDMAAddyInt32(DWORD ptr, std::vector<DWORD> offsets)
	{
		DWORD addr{ ptr };
		for (unsigned int i = 0; i < offsets.size(); ++i)
		{
			addr = *(DWORD*)addr;
			addr += offsets[i];
		}
		return addr;
	}

	DWORD WindowsBackend::GetQSIBufferSizeNt(const SYSTEM_INFORMATION_CLASS sInfoClass)
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

	std::wstring WindowsBackend::ReadRemoteUnicodeStringNt(HANDLE hProcess, const UNICODE_STRING& unicodeString)
	{
		if (!unicodeString.Buffer || !unicodeString.Length) return {};
		std::wstring s(unicodeString.Length / sizeof(wchar_t), L'\0');

		NtReadVirtualMemory(
			hProcess,
			reinterpret_cast<PVOID>(unicodeString.Buffer),
			s.data(),
			unicodeString.Length,
			nullptr);

		return s;
	}
#pragma endregion
#pragma endregion

	/*std::vector<BackendWin32> BackendWin32::GetProcessListW32()
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
	}*/

	/* std::vector<BackendNt> BackendNt::GetProcessListNt()
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
	*/
}