#pragma once
#include <windows.h>
#include <vector>
#include <string>
#include <stdexcept>

namespace corvus::process
{
	enum class ArchitectureType : uint8_t // BYTE
	{
		Unknown = 0,
		Native = 1,
		x86 = 2,
		x64 = 3,
		arm = 4,
		arm64 = 5
	};

	enum class HandleType : uint8_t // BYTE
	{
		Unknown = 0,
		Process = 1,
		Thread = 2,
		File = 3,
		Section = 4,
		Mutex = 5,
		Event = 6,
		RegistryKey = 7,
		Socket = 8,
		Heap = 9
	};

	struct Module
	{
		std::wstring description{}; // UTF-16 string (heap-allocated, size varies)
		uintptr_t baseAddress{}; // x86: 32 bits, x64 : 64 bits
		SIZE_T size{}; // x86: 32 bits, x64 : 64 bits
	};

	struct Thread
	{
		std::wstring description{}; // UTF-16 string (heap-allocated, size varies)
		DWORD threadId{}; // 32 bits
		DWORD ownerPid{}; // 32 bits
		LONG priority{}; // 32 bits
	};

	struct Handle
	{
		DWORD ownerPid{}; // 32 bits
		ACCESS_MASK grantedAccess{}; // 32 bits
		USHORT handleValue{}; // NT handle index, 16 bits
		HandleType type{ HandleType::Unknown }; // 8 bits
		BYTE objectTypeNumber{}; // NT object type index, 8 bits
		BYTE flags{}; // 8 bits
		HANDLE handle{}; // void*
		PVOID object{}; // void*
	};

	class IProcess
	{
	public:
		virtual ~IProcess() noexcept = default;

		// virtual const noexcept getters
		virtual const std::wstring& GetName() const noexcept = 0;
		virtual const std::vector<Module>& GetModules() const noexcept = 0;
		virtual const std::vector<Thread>& GetThreads() const noexcept = 0;
		virtual const std::vector<Handle>& GetHandles() const noexcept = 0;
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
		std::vector<Module> m_modules{}; // (heap-allocated, size varies)
		std::vector<Thread> m_threads{}; // (heap-allocated, size varies)
		std::vector<Handle> m_handles{}; // (heap-allocated, size varies)
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
		const std::vector<Module>& GetModules() const noexcept override { return m_modules; }
		const std::vector<Thread>& GetThreads() const noexcept override { return m_threads; }
		const std::vector<Handle>& GetHandles() const noexcept override { return m_handles; }
		uintptr_t GetModuleBaseAddress() const noexcept override { return m_moduleBaseAddress; }
		uintptr_t GetPEBAddress() const noexcept override { return m_pebAddress; }
		DWORD GetProcessId() const noexcept override { return m_processId; }
		ArchitectureType GetArchitecture() const noexcept override { return m_architectureType; }
		BOOL IsWow64() const noexcept override { return m_isWow64; }
		BOOL HasVisibleWindow() const noexcept override { return m_hasVisibleWindow; }

		// static noexcept validators
		static inline bool IsValidProcessId(const DWORD processId) noexcept { return processId != 0; }
		static inline bool IsValidModuleBaseAddress(const DWORD moduleBaseAddress) noexcept { return moduleBaseAddress != 0; }
		static inline bool IsValidHandle(const HANDLE processHandle) noexcept { return (processHandle != nullptr && processHandle != INVALID_HANDLE_VALUE); }
	};

	class WIN32Process : public WindowsProcessBase
	{
	private:
		void QueryNameW32();
		void QueryModulesW32();
		void QueryThreadsW32();
		void QueryHandlesW32();
		void QueryModuleBaseAddressW32();
		void QueryPEBAddressW32();
		void QueryArchitectureTypeW32();
		void QueryWow64W32();
		void QueryVisibleWindowW32();

	public:
		WIN32Process() = delete;
		explicit WIN32Process(const DWORD processId);
		~WIN32Process() noexcept override = default;

		// static process functions
		static std::vector<WIN32Process> GetProcessListW32();
		static HANDLE OpenProcessHandleW32(const DWORD processId, const ACCESS_MASK accessMask);
		static uintptr_t GetModuleBaseAddress(const DWORD& processId, const std::wstring& moduleName);
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
}