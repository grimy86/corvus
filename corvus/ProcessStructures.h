#pragma once
#include <Windows.h>
#include <string>
#include "ntdll.h"

#ifndef UNDEFINED_PRIORITY_CLASS
#define UNDEFINED_PRIORITY_CLASS 0x00000000
#endif // !UNDEFINED_PRIORITY_CLASS

namespace Corvus::Object
{
	/// <summary>
	/// Flags struct @ LDR_DATA_TABLE_ENTRY, ntdll.h
	/// </summary>
	enum class KernelModuleFlags : DWORD
	{
		PackagedBinary = 0b1UL << 0,
		MarkedForRemoval = 0b1UL << 1,
		ImageDll = 0b1UL << 2,
		LoadNotificationsSent = 0b1UL << 3,
		TelemetryEntryProcessed = 0b1UL << 4,
		ProcessStaticImport = 0b1UL << 5,
		InLegacyLists = 0b1UL << 6,
		InIndexes = 0b1UL << 7,
		ShimDll = 0b1UL << 8,
		InExceptionTable = 0b1UL << 9,
		VerifierProvider = 0b1UL << 10, // 24H2
		ShimEngineCalloutSent = 0b1UL << 11, // 24H2
		LoadInProgress = 0b1UL << 12,
		LoadConfigProcessed = 0b1UL << 13, // WIN10
		EntryProcessed = 0b1UL << 14,
		ProtectDelayLoad = 0b1UL << 15, // WINBLUE
		AuxIatCopyPrivate = 0b1UL << 16, // 24H2
		ReservedFlags3 = 0b1UL << 17,
		DontCallForThreads = 0b1UL << 18,
		ProcessAttachCalled = 0b1UL << 19,
		ProcessAttachFailed = 0b1UL << 20,
		ScpInExceptionTable = 0b1UL << 21, // CorDeferredValidate before 24H2
		CorImage = 0b1UL << 22,
		DontRelocate = 0b1UL << 23,
		CorILOnly = 0b1UL << 24,
		ChpeImage = 0b1UL << 25, // RS4
		ChpeEmulatorImage = 0b1UL << 26, // WIN11
		ReservedFlags5 = 0b1UL << 27,
		Redirected = 0b1UL << 28,
		ReservedFlags6 = 0b11UL << 29, // 2 bits
		CompatDatabaseProcessed = 0b1UL << 31
	};

	enum class UserThreadBasePriority : LONG
	{
		Idle = THREAD_PRIORITY_IDLE, // -15 or THREAD_BASE_PRIORITY_IDLE
		Lowest = THREAD_PRIORITY_LOWEST, // -2 or THREAD_BASE_PRIORITY_MIN
		BelowNormal = THREAD_PRIORITY_BELOW_NORMAL, // -1 or (THREAD_PRIORITY_LOWEST + 1)
		Normal = THREAD_PRIORITY_NORMAL, // 0
		AboveNormal = THREAD_PRIORITY_ABOVE_NORMAL, // 1 or (THREAD_PRIORITY_HIGHEST - 1)
		Highest = THREAD_PRIORITY_HIGHEST, // 2 or THREAD_BASE_PRIORITY_MAX
		TimeCritical = THREAD_PRIORITY_TIME_CRITICAL, // 15 or THREAD_BASE_PRIORITY_LOWRT
		Error = THREAD_PRIORITY_ERROR_RETURN, // 0x7FFFFFFF or (MAXLONG)
	};

	enum class KernelThreadBasePriority : KPRIORITY
	{
		Idle = 0L,
		Lowest = 1L,
		BelowNormal = 2L,
		Normal = 8L,
		AboveNormal = 10L,
		Highest = 15L,
		TimeCritical = 31L,
		Unknown = 0xFF
	};

	enum class UserProcessBasePriorityClass : DWORD
	{
		Undefined = UNDEFINED_PRIORITY_CLASS, // 0x0
		Normal = NORMAL_PRIORITY_CLASS, // 0x20
		Idle = IDLE_PRIORITY_CLASS, // 0x40
		High = HIGH_PRIORITY_CLASS, // 0x80
		Realtime = REALTIME_PRIORITY_CLASS, // 0x100
		BelowNormal = BELOW_NORMAL_PRIORITY_CLASS, // 0x4000
		AboveNormal = ABOVE_NORMAL_PRIORITY_CLASS // 0x8000
	};

	/// <summary>
	/// This is a specific structure for user object handles, not kernel handles.
	/// <para> Kernel object handles, UCHAR ObjectTypeIndex @ OBJECT_TYPE_INFORMATION. </para>
	/// <para> The ObjectTypeIndex may be subject to change accross Windows versions. </para>
	/// </summary>
	enum class UserHandleObjectType : uint8_t
	{
		Unknown = 0,
		Process = 1,
		Thread = 2,
		Mutant = 3,
		Event = 4,
		Section = 5,
		// BUGBUG WINBLUE 571662 2013-12-31 GenghisK: #ifdef this for OS after
		// WINBLUE
		Semaphore = 6
	};

	enum class ArchitectureType : uint8_t
	{
		Unknown,
		x86,
		x64
	};

	/// <summary>
	/// MODULEENTRY32W, Tlhelp32.h wrapper
	/// <para> MODULEINFO, Psapi.h wrapper </para>
	/// <para> LDR_DATA_TABLE_ENTRY, ntdll.h wrapper </para>
	/// </summary>
	struct ModuleEntry
	{
		/// <summary>
		/// WCHAR szModule[MAX_MODULE_NAME32 + 1] @ MODULEENTRY32
		/// <para> UNICODE_STRING BaseDllName @ LDR_DATA_TABLE_ENTRY </para>
		/// </summary>
		std::wstring moduleName{};

		/// <summary>
		/// WCHAR szExePath[MAX_PATH] @ MODULEENTRY32
		/// <para> UNICODE_STRING FullDllName @ LDR_DATA_TABLE_ENTRY </para>
		/// </summary>
		std::wstring modulePath{};

		/// <summary>
		/// LPVOID lpBaseOfDll @ MODULEINFO
		/// <para> PVOID DllBase @ LDR_DATA_TABLE_ENTRY </para>
		/// </summary>
		uintptr_t moduleLoadAddress{};
		uintptr_t moduleEntryPoint{};
		uintptr_t moduleBaseAddress{};
		uintptr_t parentDllBaseAddress{};
		SIZE_T moduleBaseSize{};

		/// <summary>
		/// Use KernelModuleFlags structure for mapping
		/// </summary>
		DWORD kernelModuleFlags{};
		DWORD moduleImageSize{};
		DWORD processId{};
		WORD tlsIndex{};
	};

	/// <summary>
	/// THREADENTRY32 @ Tlhelp32.h
	/// <para> SYSTEM_EXTENDED_THREAD_INFORMATION @ ntdll.h </para>
	/// </summary>
	struct ThreadEntry
	{
		/// <summary>
		///  PVOID StartAddress @ SYSTEM_THREAD_INFORMATION
		/// </summary>
		uintptr_t kernelThreadStartAddress{};

		/// <summary>
		///  PVOID Win32StartAddress @ SYSTEM_EXTENDED_THREAD_INFORMATION
		/// </summary>
		uintptr_t userThreadStartAddress{};
		uintptr_t tebBaseAddress{};

		/// <summary>
		/// LONG tpBasePri @ THREADENTRY32
		/// </summary>
		UserThreadBasePriority userThreadBasePriority{};

		/// <summary>
		/// KPRIORITY BasePriority @ SYSTEM_THREAD_INFORMATION
		/// </summary>
		KernelThreadBasePriority kernelThreadBasePriority{};

		/// <summary>
		/// DWORD th32ThreadID @ THREADENTRY32
		/// <para> CLIENT_ID ClientId @ SYSTEM_THREAD_INFORMATION</para>
		/// </summary>
		DWORD threadId{};
		DWORD threadOwnerProcessId{};
	};

	/// <summary>
	/// PSS_HANDLE_ENTRY @ processsnapshot.h
	/// <para> SYSTEM_HANDLE_TABLE_ENTRY_INFO @ ntdll.h </para>
	/// </summary>
	struct HandleEntry
	{
		/// <summary>
		/// UNICODE_STRING TypeName @ OBJECT_TYPE_INFORMATION
		/// </summary>
		std::wstring typeName{};
		std::wstring objectName{};
		uintptr_t handleValue{};
		ACCESS_MASK grantedAccess{};

		/// <summary>
		/// Based on <see cref="UserHandleObjectType"/>
		/// </summary>
		DWORD userTargetProcessId{};

		/// <summary>
		/// PSS_OBJECT_TYPE ObjectType field @ PSS_HANDLE_ENTRY
		/// </summary>
		UserHandleObjectType userHandleObjectType{};
	};

	/// <summary>
	/// PROCESSENTRY32W @ Tlhelp32.h
	/// <para> QueryFullProcessImageNameW @ WinBase.h </para>
	/// <para> SYSTEM_PROCESS_INFORMATION @ ntdll.h </para>
	/// <para> PROCESS_EXTENDED_BASIC_INFORMATION @ ntdll.h </para>
	/// </summary>
	struct ProcessEntry
	{
		/// <summary>
		/// The file name of the executable image.
		/// <para> WCHAR szExeFile[MAX_PATH] @ PROCESSENTRY32W </para>
		/// <para> UNICODE_STRING ImageName @ SYSTEM_PROCESS_INFORMATION </para>
		/// </summary>
		std::wstring processName{};

		/// <summary>
		/// LPWSTR lpExeName @ QueryFullProcessImageNameW()
		/// </summary>
		std::wstring userFullProcessImageName{};

		/// <summary>
		/// UNICODE_STRING SystemInformation @ NtQueryInformationProcess()
		/// <para> Arg: PROCESSINFOCLASS::ProcessImageFileName (27) </para>
		/// </summary>
		std::wstring kernelImageFilePath{};
		uintptr_t pebBaseAddress{};
		uintptr_t moduleBaseAddress{};

		/// <summary>
		/// LONG pcPriClassBase @ PROCESSENTRY32W
		/// </summary>
		UserProcessBasePriorityClass userProcessBasePriorityClass{};

		/// <summary>
		/// The starting priority of the process.
		/// <para> Undocumented! </para>
		/// </summary>
		KPRIORITY kernelProcessBasePriority{};
		DWORD processId{};
		DWORD parentProcessId{};
		BOOL isWow64{};
		BOOL isProtectedProcess{};
		BOOL isBackgroundProcess{};
		BOOL isSecureProcess{};
		BOOL isSubsystemProcess{};
		BOOL hasVisibleWindow{};
		ArchitectureType architectureType{};
	};
}