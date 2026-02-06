#pragma once
#include <windows.h>
#include <ProcessSnapshot.h>
#include <vector>
#include <string>
#include <stdexcept>
#include "ntdll.h"

namespace corvus::process
{
#pragma region DataStructures
	enum class ArchitectureType : uint8_t // BYTE
	{
		Unknown,
		x86,
		x64
	};

	enum class HandleType : uint8_t
	{
		Unknown = 0,
		Process,
		Thread,
		Mutant,
		Event,
		Section,
		Semaphore,
		File,
		Key,
		Token
	};

	enum class PriorityClass : DWORD
	{
		Undefined = 0x0,
		Idle = IDLE_PRIORITY_CLASS,
		Normal = NORMAL_PRIORITY_CLASS,
		High = HIGH_PRIORITY_CLASS,
		Realtime = REALTIME_PRIORITY_CLASS,
		BelowNormal = BELOW_NORMAL_PRIORITY_CLASS,
		AboveNormal = ABOVE_NORMAL_PRIORITY_CLASS
	};

	struct ModuleEntry
	{
		// Win32 structure members
		std::wstring moduleName{}; // UTF-16 string (heap-allocated, size varies)
		std::wstring modulePath{}; // UTF-16 string (heap-allocated, size varies)
		SIZE_T size{}; // 32 | 64 bits
		uintptr_t baseAddress{}; // 32 | 64 bits
		SIZE_T moduleBaseSize{}; // 32 | 64 bits
		LPVOID entryPoint{}; // 32 | 64 bits
		DWORD processId{}; // 32 bits
		DWORD globalLoadCount{}; // 32 bits
		DWORD processLoadCount{}; // 32 bits
	};

	struct ThreadEntry
	{
		// Win32 structure members
		SIZE_T size{}; // 32 bits
		DWORD threadId{}; // 32 bits
		DWORD ownerProcessId{}; // 32 bits
		LONG basePriority{}; // 32 bits

		// Nt structure members
		PVOID startAddress{};
		KTHREAD_STATE threadState{};
		KWAIT_REASON waitReason{};
	};

	struct HandleEntry
	{
		std::wstring typeName{}; // UTF-16 string (heap-allocated, size varies)
		std::wstring objectName{}; // UTF-16 string (heap-allocated, size varies)
		HANDLE handle{}; // x86: 32 bits, x64: 64 bits
		DWORD flags{}; // 32 bits
		DWORD attributes{}; // 32 bits
		DWORD grantedAccess{}; // 32 bits
		DWORD handleCount{}; // 32 bits
		DWORD targetProcessId{}; // 32 bits
		PSS_OBJECT_TYPE pssObjectType{}; // 32 bits
	};

	struct ProcessEntry
	{
		std::wstring name{}; // UTF-16 string (heap-allocated, size varies)
		std::wstring imageFilePath{}; // UTF-16 string (heap-allocated, size varies)
		uintptr_t moduleBaseAddress{}; // x86: 32 bits, x64: 64 bits
		uintptr_t pebAddress{}; // x86: 32 bits, x64: 64 bits
		DWORD processId{}; // 32 bits
		DWORD parentProcessId{}; // 32 bits
		PriorityClass priorityClass{}; // 32 bits
		BOOL isWow64{}; // 32 bits
		BOOL isProtectedProcess{}; // 32 bits
		BOOL isBackgroundProcess{}; // 32 bits
		BOOL isSecureProcess{}; // 32 bits
		BOOL isSubsystemProcess{}; // 32 bits
		BOOL hasVisibleWindow{}; // 32 bits
		ArchitectureType architectureType{}; // 8 bits
	};

	struct AccessBit
	{
		DWORD bit;
		const char* name;
	};
#pragma endregion

#pragma region Processes
	class WindowsProcess
	{
	protected:
		HANDLE m_processHandle{};
		ProcessEntry m_process{};
		std::vector<ModuleEntry> m_modules{};
		std::vector<ThreadEntry> m_threads{};
		std::vector<HandleEntry> m_handles{};

		WindowsProcess() = delete;
		explicit WindowsProcess(const DWORD processId)
			: m_processEntry{}
		{
			if (!IsValidProcessId(processId)) throw std::invalid_argument("Invalid PID");
			else m_processEntry.processId = processId;

			m_processHandle = corvus::process::BackendNt::OpenProcessHandleNt(processId, PROCESS_ALL_ACCESS);
			if (!IsValidHandle(m_processHandle)) m_processHandle = corvus::process::BackendNt::OpenProcessHandleNt(processId, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);
			if (!IsValidHandle(m_processHandle)) m_processHandle = corvus::process::BackendNt::OpenProcessHandleNt(processId, PROCESS_QUERY_LIMITED_INFORMATION);
			if (!IsValidHandle(m_processHandle)) m_processHandle = INVALID_HANDLE_VALUE;
		};
		~WindowsProcess()
		{
			if (IsValidHandle(m_processHandle))
			{
				NtClose(m_processHandle);
				m_processHandle = INVALID_HANDLE_VALUE;
			}
		};

	public:
		// getters
		const std::wstring& GetProcessEntryName() const noexcept;
		const std::string& GetProcessEntryNameA() const noexcept;
		const std::wstring& GetProcessEntryImageFilePath() const noexcept;
		std::string GetProcessEntryImageFilePathA() const noexcept;
		const std::vector<ModuleEntry>& GetProcessEntryModules() const noexcept;
		const std::vector<ThreadEntry>& GetProcessEntryThreads() const noexcept;
		const std::vector<HandleEntry>& GetProcessEntryHandles() const noexcept;
		uintptr_t GetModuleBaseAddress() const noexcept;
		uintptr_t GetPEBAddress() const noexcept;
		DWORD GetProcessId() const noexcept;
		std::string GetProcessIdA() const noexcept;
		DWORD GetParentProcessId() const noexcept;
		PriorityClass GetPriorityClass() const noexcept;
		const char* GetPriorityClassA() const noexcept;
		BOOL IsWow64() const noexcept;
		BOOL IsProtectedProcess() const noexcept;
		BOOL IsBackgroundProcess() const noexcept;
		BOOL IsSecureProcess() const noexcept;
		BOOL IsSubsystemProcess() const noexcept;
		BOOL HasVisibleWindow() const noexcept;
		ArchitectureType GetArchitectureType() const noexcept;
		const char* GetArchitectureTypeA() const noexcept;

		// validators
		static bool IsValidProcessId(const DWORD processId) noexcept;
		static bool IsValidModuleBaseAddress(const DWORD moduleBaseAddress) noexcept;
		static bool IsValidHandle(const HANDLE processHandle) noexcept;

		// converters
		static std::string ToString(const std::wstring& wstring) noexcept;
		static std::string ToString(DWORD processId) noexcept;
		static const char* ToString(ArchitectureType arch) noexcept;
		static const char* ToString(PriorityClass priorityClass) noexcept;
		static const char* MapAccess(std::wstring type, DWORD access) noexcept;
		static const char* MapAttributes(DWORD attribute) noexcept;
	};
#pragma endregion

#pragma region Backends
	class BackendWin32
	{
	private:
		BackendWin32() = delete;
		~BackendWin32() = delete;
		
	public:
		// queries
		static void QueryArchitecture(HANDLE hProcess, DWORD processId);
		static void QueryVisibleWindow(HANDLE hProcess, DWORD processId);
		static void QueryImageFilePath(HANDLE hProcess, DWORD processId);
		static void QueryPriorityClass(HANDLE hProcess, DWORD processId);
		static void QueryModuleBaseAddress(HANDLE hProcess, DWORD processId);
		static void QueryModules(HANDLE hProcess, DWORD processId);
		static void QueryThreads(HANDLE hProcess, DWORD processId);
		static void QueryHandles(HANDLE hProcess, DWORD processId);

		// os-interfacing, E = external I = internal
		static HANDLE OpenProcessHandleW32(const DWORD processId, const ACCESS_MASK accessMask);
		static std::string GetProcessNameW32(DWORD pid);
		static BOOL SuspendThreadW32(const DWORD threadId);
		static BOOL ResumeThreadW32(const DWORD threadId);
		static BOOL EnableSeDebugPrivilegeW32();
		static BOOL EnableSeDebugPrivilegeW32(const DWORD processId);
		static BOOL SetThreadPriorityW32(int priorityMask);
		static bool IsSeDebugPrivilegeEnabledW32();
		static bool IsThreadPrioritySetW32(int priorityMask);
		static void PatchExecutionEW32(HANDLE processHandle, DWORD destination, BYTE* value, unsigned int size);
		static void NopExecutionEW32(HANDLE processHandle, DWORD destination, unsigned int size);
		static DWORD FindDMAAddyEW32(HANDLE processHandle, DWORD ptr, std::vector<DWORD> offsets);
		static void PatchExecutionIW32(DWORD destination, BYTE* value, unsigned int size);
		static void NopExecutionIW32(DWORD destination, unsigned int size);
		static DWORD FindDMAAddyIW32(DWORD ptr, std::vector<DWORD> offsets);

		// templates
		template <typename T>
		static T ReadFromMemoryEW32(const HANDLE processHandle, const uintptr_t readAddress)
		{
			T returnValue{};

			ReadProcessMemory(
				processHandle,
				reinterpret_cast<LPCVOID>(readAddress),
				reinterpret_cast<LPVOID>(&returnValue),
				sizeof(returnValue),
				nullptr
			);

			return returnValue;
		}

		template <typename T>
		static bool WriteProcessMemoryEW32(const HANDLE processHandle, const uintptr_t writeAddress, const T& writeValue)
		{
			return static_cast<bool>(WriteProcessMemory(
				processHandle,
				reinterpret_cast<LPVOID>(writeAddress),
				reinterpret_cast<LPCVOID>(&writeValue),
				sizeof(writeValue),
				nullptr
			));
		}
	};

	class BackendNt
	{
	private:
		BackendNt() = delete;
		~BackendNt() = delete;

	public:
		// queries
		static void QueryExtendedProcessInfoNt(HANDLE hProc, BackendNt& proc);
		static void QueryArchitectureNt(HANDLE hProc, BackendNt& proc);
		static void QueryVisibleWindowNt(HANDLE hProc, BackendNt& proc);
		static void QueryImageFilePathNt(HANDLE hProc, BackendNt& proc);
		static void QueryPriorityClassNt(HANDLE hProc, BackendNt& proc);
		static void QueryModuleBaseAddressNt(HANDLE hProc, BackendNt& proc);
		static void QueryModules(HANDLE hProcess, DWORD processId);
		static void QueryThreads(HANDLE hProcess, DWORD processId);
		static void QueryHandles(HANDLE hProcess, DWORD processId);

		// os-interfacing, E = external I = internal
		std::wstring QueryObjectNameNt(HANDLE h) noexcept;
		std::wstring QueryObjectTypeName(HANDLE h) noexcept;
		static HANDLE OpenProcessHandleNt(const DWORD processId, const ACCESS_MASK accessMask);
		static DWORD GetQSIBufferSizeNt(const SYSTEM_INFORMATION_CLASS sInfoClass);
		static std::wstring ReadRemoteUnicodeStringNt(HANDLE hProc, const UNICODE_STRING& us);

		// templates
		template <typename T>
		T ReadVirtualMemoryNt(HANDLE hProc, uintptr_t baseAddress)
		{
			T result{};
			NtReadVirtualMemory(
				hProc,
				reinterpret_cast<PVOID>(baseAddress),
				&result,
				sizeof(T),
				nullptr);
			return result;
		}
	};
#pragma endregion
}