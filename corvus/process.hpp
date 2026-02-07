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
		SIZE_T structureSize{}; // 32 | 64 bits
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
		SIZE_T structureSize{}; // 32 bits
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

#pragma region Process
	class WindowsProcess
	{
	protected:
		HANDLE m_processHandle{};
		ProcessEntry m_process{};
		std::vector<ModuleEntry> m_modules{};
		std::vector<ThreadEntry> m_threads{};
		std::vector<HandleEntry> m_handles{};

		explicit WindowsProcess(const DWORD processId);
		~WindowsProcess();
		WindowsProcess() = delete;
		WindowsProcess(const WindowsProcess&) = delete;
		WindowsProcess& operator=(const WindowsProcess&) = delete;

	public:
		// getters
		const std::wstring& GetProcessEntryName() const noexcept;
		const std::string& GetProcessEntryNameA() const noexcept;
		const std::wstring& GetProcessEntryImageFilePath() const noexcept;
		const std::string& GetProcessEntryImageFilePathA() const noexcept;
		const std::vector<ModuleEntry>& GetModules() const noexcept;
		const std::vector<ThreadEntry>& GetThreads() const noexcept;
		const std::vector<HandleEntry>& GetHandles() const noexcept;
		uintptr_t GetModuleBaseAddress() const noexcept;
		uintptr_t GetPEBAddress() const noexcept;
		DWORD GetProcessId() const noexcept;
		HANDLE GetProcessHandle() const noexcept;
		const std::string& GetProcessIdA() const noexcept;
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

		// converters
		static std::string ToString(const std::wstring& wstring) noexcept;
		static std::string ToString(DWORD processId) noexcept;
		static const char* ToString(ArchitectureType arch) noexcept;
		static const char* ToString(PriorityClass priorityClass) noexcept;
		static const char* MapAccess(std::wstring type, DWORD access) noexcept;
		static const char* MapAttributes(DWORD attribute) noexcept;
	};
#pragma endregion

#pragma region Backend
	class WindowsBackend
	{
	private:
		WindowsBackend() = delete;
		~WindowsBackend() = delete;

	public:
		// validators
		static bool IsValidProcessId(const DWORD processId) noexcept;
		static bool IsValidAddress(const DWORD moduleBaseAddress) noexcept;
		static bool IsValidHandle(const HANDLE processHandle) noexcept;

		// queries
		static PROCESS_EXTENDED_BASIC_INFORMATION QueryExtendedProcessInfoNt(HANDLE hProcess);
		static std::wstring QueryProcessName32(DWORD processId);
		static std::wstring QueryImageFilePath32(HANDLE hProcess);
		static std::wstring QueryImageFilePathNt(HANDLE hProcess);
		static std::vector<ModuleEntry> QueryModules32(HANDLE hProcess, DWORD processId);
		static std::vector<ModuleEntry> QueryModulesNt(HANDLE hProcess, PROCESS_EXTENDED_BASIC_INFORMATION& pInfo);
		static std::vector<ThreadEntry> QueryThreads32(HANDLE hProcess, DWORD processId);
		static std::vector<HandleEntry> QueryHandles32(HANDLE hProcess, DWORD processId);
		static std::vector<HandleEntry> QueryHandlesNt(DWORD processId);
		static uintptr_t QueryModuleBaseAddress32(DWORD processId, const std::wstring& processName);
		static PriorityClass QueryPriorityClass32(HANDLE hProcess);
		static PriorityClass QueryPriorityClassNt(HANDLE hProcess);
		static bool QueryVisibleWindow32(DWORD processId);
		static ArchitectureType QueryArchitecture32(HANDLE hProcess, bool& isWow64);
		static ArchitectureType QueryArchitectureNt(HANDLE hProcess);
		static bool QuerySeDebugPrivilege32(HANDLE hProcess);
		static int QueryThreadPriority32(HANDLE hThread);
		static std::wstring QueryObjectNameNt(HANDLE hObject, DWORD processId);
		static std::wstring QueryObjectTypeNameNt(HANDLE hObject, DWORD processId);

		// operations
		static HANDLE OpenProcessHandle32(const DWORD processId, const ACCESS_MASK accessMask);
		static HANDLE OpenProcessHandleNt(const DWORD processId, const ACCESS_MASK accessMask);
		static BOOL SuspendThread32(const DWORD threadId);
		static BOOL ResumeThread32(const DWORD threadId);
		static BOOL EnableSeDebugPrivilege32();
		static BOOL EnableSeDebugPrivilege32(const DWORD processId);
		static BOOL SetThreadPriority32(int priorityMask);
		static void PatchExecutionExt32(HANDLE processHandle, DWORD destination, BYTE* value, unsigned int size);
		static void PatchExecutionInt32(DWORD destination, BYTE* value, unsigned int size);
		static void NopExecutionExt32(HANDLE processHandle, DWORD destination, unsigned int size);
		static void NopExecutionInt32(DWORD destination, unsigned int size);
		static DWORD FindDMAAddyExt32(HANDLE processHandle, DWORD ptr, std::vector<DWORD> offsets);
		static DWORD FindDMAAddyInt32(DWORD ptr, std::vector<DWORD> offsets);
		static DWORD GetQSIBufferSizeNt(const SYSTEM_INFORMATION_CLASS sInfoClass);
		static std::wstring ReadRemoteUnicodeStringNt(HANDLE hProcess, const UNICODE_STRING& unicodeString);

		// templates
		template <typename T>
		static bool ReadProcessMemoryExt32(const HANDLE processHandle, const uintptr_t readAddress)
		{
			T returnValue{};
			return static_cast<bool>(ReadProcessMemory(
				processHandle,
				reinterpret_cast<LPCVOID>(readAddress),
				reinterpret_cast<LPVOID>(&returnValue),
				sizeof(returnValue),
				nullptr
			));
			return returnValue;
		}

		template <typename T>
		static bool WriteProcessMemoryExt32(const HANDLE processHandle, const uintptr_t writeAddress, const T& writeValue)
		{
			return static_cast<bool>(WriteProcessMemory(
				processHandle,
				reinterpret_cast<LPVOID>(writeAddress),
				reinterpret_cast<LPCVOID>(&writeValue),
				sizeof(writeValue),
				nullptr
			));
		}

		template <typename T>
		static NTSTATUS ReadVirtualMemoryNt(HANDLE hProc, uintptr_t baseAddress, T& out)
		{
			return NtReadVirtualMemory(
				hProc,
				reinterpret_cast<PVOID>(baseAddress),
				&out,
				sizeof(T),
				nullptr
			);
		}
	};
#pragma endregion
}