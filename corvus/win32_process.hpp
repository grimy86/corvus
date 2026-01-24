#pragma once
#include <windows.h>
#include <vector>
#include <string>

namespace corvus::process
{
	enum class Architecture : uint8_t // BYTE
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

	struct WindowsModule
	{
		std::wstring description{}; // UTF-16 string (heap-allocated, size varies)
		uintptr_t baseAddress{}; // x86: 32 bits, x64 : 64 bits
		SIZE_T size{}; // x86: 32 bits, x64 : 64 bits
	};

	struct ProcessThread
	{
		std::wstring description{}; // UTF-16 string (heap-allocated, size varies)
		DWORD threadId{}; // 32 bits
		DWORD ownerPid{}; // 32 bits
		LONG priority{}; // 32 bits
	};

	struct ProcessHandle
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

	class WindowsProcess
	{
	public:
		explicit WindowsProcess(const DWORD processId);
		~WindowsProcess() = default;

	private:
		std::wstring name{}; // UTF-16 string (heap-allocated, size varies)
		std::vector<WindowsModule> modules{};
		std::vector<ProcessThread> threads{};
		std::vector<ProcessHandle> handles{};
		uintptr_t moduleBaseAddress{}; // x86: 32 bits, x64: 64 bits
		uintptr_t pebAddress{}; // x86: 32 bits, x64: 64 bits
		DWORD processId{}; // 32 bits
		Architecture architecture{}; // 8 bits
		BOOL isWow64{}; // 8 bits
		BOOL hasVisibleWindow{}; // 8 bits

	private:
		void QueryName();
		void QueryModules();
		void QueryThreads();
		void QueryHandles();
		void QueryModuleBaseAddress();
		void QueryPEBAddress();
		void QueryArchitecture();
		void QueryWow64();
		void QueryVisibleWindow();

	public:
		inline const std::wstring& GetName() const { return name; }
		inline const std::vector<WindowsModule>& GetModules() const { return modules; }
		inline const std::vector<ProcessThread>& GetThreads() const { return threads; }
		inline const std::vector<ProcessHandle>& GetHandles() const { return handles; }
		inline const uintptr_t GetModuleBaseAddress() const { return moduleBaseAddress; }
		inline const uintptr_t GetPEBAddress() const { return pebAddress; }
		inline const DWORD GetProcessId() const { return processId; }
		inline const Architecture GetArchitecture() const { return architecture; }
		inline const BOOL IsWow64() const { return isWow64; }
		inline const BOOL HasVisibleWindow() const { return hasVisibleWindow; }

	public:
		// Processes
		static std::vector<WindowsProcess> GetProcessList();
		static HANDLE OpenProcessHandle(const DWORD processId, const ACCESS_MASK accessMask);
		static uintptr_t GetModuleBaseAddress(const DWORD& processId, const std::wstring& moduleName);
		static bool SuspendThreadById(const DWORD threadId);
		static bool ResumeThreadById(const DWORD threadId);

		// Validators
		static inline bool IsValidProcessId(const DWORD processId) { return processId != 0; }
		static inline bool IsValidModuleBaseAddress(const DWORD moduleBaseAddress) { return moduleBaseAddress != 0; }
		static inline bool IsValidHandle(const HANDLE processHandle) { return (processHandle != nullptr && processHandle != INVALID_HANDLE_VALUE); }

		// External
		static void PatchExecution(HANDLE processHandle, DWORD destination, BYTE* value, unsigned int size);
		static void NopExecution(HANDLE processHandle, DWORD destination, unsigned int size);
		static DWORD FindDMAAddy(HANDLE processHandle, DWORD ptr, std::vector<DWORD> offsets);

		// Internal
		static void PatchExecutionI(DWORD destination, BYTE* value, unsigned int size);
		static void NopExecutionI(DWORD destination, unsigned int size);
		static DWORD FindDMAAddyI(DWORD ptr, std::vector<DWORD> offsets);

	public:
		// Templates
		template <typename T>
		static T ReadFromMemory(const HANDLE processHandle, const uintptr_t readAddress)
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
		static bool WriteToMemory(const HANDLE processHandle, const uintptr_t writeAddress, const T& writeValue)
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