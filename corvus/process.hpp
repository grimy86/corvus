#pragma once
#include <windows.h>
#include <vector>
#include <string>
#include <stdexcept>
#include "ntdll.h"

namespace corvus::process
{
	enum class ArchitectureType : uint8_t // BYTE
	{
		Unknown,
		Native,
		x86,
		x64,
		arm,
		arm64
	};

	enum class HandleType : uint8_t // BYTE
	{
		Unknown,
		Process,
		Thread,
		Mutant,
		Event,
		Section,
		Semaphore
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
		LONG deltaPriority{}; // 32 bits
		DWORD flags{}; // 32 bits

		// Nt structure members
		PVOID StartAddress{};
		KTHREAD_STATE ThreadState{};
		KWAIT_REASON WaitReason{};
	};

	struct HandleEntry
	{
		std::wstring TypeName{}; // UTF-16 string (heap-allocated, size varies)
		std::wstring ObjectName{}; // UTF-16 string (heap-allocated, size varies)
		HANDLE handle{}; // x86: 32 bits, x64: 64 bits
		DWORD flags{}; // 32 bits
		HandleType objectType{}; // 32 bits
		DWORD Attributes{}; // 32 bits
		DWORD GrantedAccess{}; // 32 bits
		DWORD HandleCount{}; // 32 bits
	};

	class IProcess
	{
	public:
		virtual ~IProcess() noexcept = default;

		// virtual const noexcept getters
		virtual const std::wstring& GetName() const noexcept = 0;
		virtual const std::vector<ModuleEntry>& GetModules() const noexcept = 0;
		virtual const std::vector<ThreadEntry>& GetThreads() const noexcept = 0;
		virtual const std::vector<HandleEntry>& GetHandles() const noexcept = 0;
		virtual uintptr_t GetModuleBaseAddress() const noexcept = 0;
		virtual uintptr_t GetPEBAddress() const noexcept = 0;
		virtual DWORD GetProcessId() const noexcept = 0;
		virtual ArchitectureType GetArchitecture() const noexcept = 0;
		virtual BOOL IsWow64() const noexcept = 0;
		virtual BOOL HasVisibleWindow() const noexcept = 0;
	};

	class WindowsProcessBase : public IProcess
	{
	protected:
		WindowsProcessBase() = delete;
		explicit WindowsProcessBase(const DWORD processId)
			: m_processId(processId)
		{
			if (!IsValidProcessId(processId))
				throw std::invalid_argument("Invalid PID");
		}

		// base members
		std::wstring m_name{}; // UTF-16 string (heap-allocated, size varies)
		std::vector<ModuleEntry> m_modules{}; // (heap-allocated, size varies)
		std::vector<ThreadEntry> m_threads{}; // (heap-allocated, size varies)
		std::vector<HandleEntry> m_handles{}; // (heap-allocated, size varies)
		uintptr_t m_moduleBaseAddress{}; // x86: 32 bits, x64: 64 bits
		uintptr_t m_pebAddress{}; // x86: 32 bits, x64: 64 bits
		DWORD m_processId{}; // 32 bits
		ArchitectureType m_architectureType{}; // 8 bits
		BOOL m_isWow64{}; // 8 bits
		BOOL m_hasVisibleWindow{}; // 8 bits

	public:
		~WindowsProcessBase() noexcept override = default;

		// const noexcept getters
		const std::wstring& GetName() const noexcept override { return m_name; }
		const std::vector<ModuleEntry>& GetModules() const noexcept override { return m_modules; }
		const std::vector<ThreadEntry>& GetThreads() const noexcept override { return m_threads; }
		const std::vector<HandleEntry>& GetHandles() const noexcept override { return m_handles; }
		uintptr_t GetModuleBaseAddress() const noexcept override { return m_moduleBaseAddress; }
		uintptr_t GetPEBAddress() const noexcept override { return m_pebAddress; }
		DWORD GetProcessId() const noexcept override { return m_processId; }
		ArchitectureType GetArchitecture() const noexcept override { return m_architectureType; }
		BOOL IsWow64() const noexcept override { return m_isWow64; }
		BOOL HasVisibleWindow() const noexcept override { return m_hasVisibleWindow; }

		// static noexcept validators
		static inline bool IsValidProcessId(const DWORD processId) noexcept { return processId % 4 == 0; }
		static inline bool IsValidModuleBaseAddress(const DWORD moduleBaseAddress) noexcept { return moduleBaseAddress != ERROR_INVALID_ADDRESS; }
		static inline bool IsValidHandle(const HANDLE processHandle) noexcept
		{
			return (processHandle != nullptr &&
				processHandle != reinterpret_cast<HANDLE>(-1) &&
				processHandle != INVALID_HANDLE_VALUE);
		}
	};

	class WindowsProcessWin32 : public WindowsProcessBase
	{
	private:
		void QueryNameW32();
		void QueryModulesW32();
		void QueryThreadsW32();
		void QueryHandlesW32();
		void QueryArchitectureTypeW32();
		void QueryWow64W32();
		void QueryVisibleWindowW32();

	public:
		WindowsProcessWin32() = delete;
		explicit WindowsProcessWin32(const DWORD processId);
		~WindowsProcessWin32() noexcept override = default;

		// static process functions
		static std::vector<WindowsProcessWin32> GetProcessListW32();
		static HANDLE OpenProcessHandleW32(const DWORD processId, const ACCESS_MASK accessMask);
		static uintptr_t GetModuleBaseAddressW32(const DWORD& processId, const std::wstring& moduleName);
		static BOOL SuspendThreadW32(const DWORD threadId);
		static BOOL ResumeThreadW32(const DWORD threadId);

		// static external memory functions
		static void PatchExecutionEW32(HANDLE processHandle, DWORD destination, BYTE* value, unsigned int size);
		static void NopExecutionEW32(HANDLE processHandle, DWORD destination, unsigned int size);
		static DWORD FindDMAAddyEW32(HANDLE processHandle, DWORD ptr, std::vector<DWORD> offsets);

		// static internal memory functions
		static void PatchExecutionIW32(DWORD destination, BYTE* value, unsigned int size);
		static void NopExecutionIW32(DWORD destination, unsigned int size);
		static DWORD FindDMAAddyIW32(DWORD ptr, std::vector<DWORD> offsets);

		// static external templated memory functions
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

	class WindowsProcessNt : public WindowsProcessBase
	{
	private:
		void QueryNameNt();
		void QueryModulesNt();
		void QueryThreadsNt();
		void QueryHandlesNt();
		void QueryModuleBaseAddressNt();
		void QueryPEBAddressNt();
		void QueryArchitectureTypeNt();
		void QueryWow64Nt();
		void QueryVisibleWindowNt();

	public:
		WindowsProcessNt() = delete;
		explicit WindowsProcessNt(const DWORD processId);
		~WindowsProcessNt() noexcept override = default;

		// static process functions
		static std::vector<WindowsProcessNt> GetProcessListNt();
		static DWORD GetQSIBuffferSizeNt(const SYSTEM_INFORMATION_CLASS sInfoClass);
		static HANDLE OpenProcessHandleNt(const DWORD processId, const ACCESS_MASK accessMask);

		// static Nt wrappers
	};
}