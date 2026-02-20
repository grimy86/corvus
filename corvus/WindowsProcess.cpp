#include "WindowsProcess.h"
#include "IProcessBackend.h"
#include "MemoryService.h"
#include <stdexcept>

namespace Corvus::Process
{
	WindowsProcess::~WindowsProcess()
	{
		if (Corvus::Memory::IsValidHandle(m_processHandle))
			m_backend->CloseBackendHandle(m_processHandle);
	};

	std::string WindowsProcess::ToString(const std::wstring& wstring)
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

	std::string WindowsProcess::ToString(DWORD processId)
	{
		return std::to_string(processId);
	}

	const char* WindowsProcess::ToString(ArchitectureType arch)
	{
		switch (arch)
		{
		case ArchitectureType::Unknown: return "Unknown";
		case ArchitectureType::x86: return "x86";
		case ArchitectureType::x64: return "x64";
		default: return "Unknown";
		}
	}

	const char* WindowsProcess::ToString(PriorityClass priorityClass)
	{
		switch (priorityClass)
		{
		case Corvus::Process::PriorityClass::Undefined: return "Undefined";
		case Corvus::Process::PriorityClass::Normal: return "Normal";
		case Corvus::Process::PriorityClass::Idle: return "Idle";
		case Corvus::Process::PriorityClass::High: return "High";
		case Corvus::Process::PriorityClass::Realtime: return "Realtime";
		case Corvus::Process::PriorityClass::BelowNormal: return "Below normal";
		case Corvus::Process::PriorityClass::AboveNormal: return "Above normal";
		default: return "Undefined";
		}
	}

	const char* WindowsProcess::DecodeAccessBits(DWORD access, const AccessBit* bits, size_t count)
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

	const char* WindowsProcess::MapAccess(std::wstring type, DWORD access)
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

	const char* WindowsProcess::MapAttributes(DWORD attribute)
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

	BOOL WindowsProcess::Init(
		const DWORD processId,
		std::unique_ptr<Corvus::Backend::IProcessBackend> backend,
		const ACCESS_MASK accessMask)
	{
		if (m_processIdSet || m_processHandleSet) return FALSE;

		if (Corvus::Memory::IsValidProcessId(processId))
		{
			m_processId = processId;
			m_processIdSet = TRUE;
			m_backend = std::move(backend);
			m_processHandle = m_backend->OpenBackendHandle(m_processId, accessMask);
			m_processHandleSet = Corvus::Memory::IsValidHandle(m_processHandle) ? TRUE : FALSE;
		}

		return m_processHandleSet;
	}

	void WindowsProcess::SwitchBackend(std::unique_ptr<Corvus::Backend::IProcessBackend> backend)
	{
		m_backend = std::move(backend);
	}

	const DWORD WindowsProcess::GetProcessId() const noexcept { return m_processId; }
	const HANDLE WindowsProcess::GetProcessHandle() const noexcept { return m_processHandle; }
	const ProcessEntry& WindowsProcess::GetProcessEntry() const noexcept { return m_processEntry; }
	const std::vector<ModuleEntry>& WindowsProcess::GetModules() const noexcept { return m_modules; }
	const std::vector<ThreadEntry>& WindowsProcess::GetThreads() const noexcept { return m_threads; }
	const std::vector<HandleEntry>& WindowsProcess::GetHandles() const noexcept { return m_handles; }

	const std::string& WindowsProcess::GetProcessEntryNameA() const noexcept { return ToString(m_processEntry.name); }
	const std::string& WindowsProcess::GetProcessEntryImageFilePathA() const noexcept { return ToString(m_processEntry.imageFilePath); }
	const std::string& WindowsProcess::GetProcessIdA() const noexcept { return ToString(m_processEntry.processId); }
	const char* WindowsProcess::GetPriorityClassA() const noexcept { return ToString(m_processEntry.priorityClass); }
	const char* WindowsProcess::GetArchitectureTypeA() const noexcept { return ToString(m_processEntry.architectureType); }
}