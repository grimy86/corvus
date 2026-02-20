#pragma once
#include <Windows.h>
#include <ProcessSnapshot.h>
#include <string>
#include "ntdll.h"

namespace Corvus::Process
{
	enum class ArchitectureType : uint8_t
	{
		Unknown,
		x86,
		x64
	};

	enum class HandleType : uint8_t
	{
		Unknown,
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
		Undefined = 0x00000000,
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
}