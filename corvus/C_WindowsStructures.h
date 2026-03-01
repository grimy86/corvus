#ifndef CORVUS_WINDOWS_STRUCTURES_H_INCLUDED
#define CORVUS_WINDOWS_STRUCTURES_H_INCLUDED
#include <stdint.h>
#include <Windows.h>
#include "ntdll.h"

/* Use WindowsStructures.h for C++
#ifdef __cplusplus
extern "C" {
#endif
*/

#ifndef UNDEFINED_PRIORITY_CLASS
#define UNDEFINED_PRIORITY_CLASS 0x00000000
#endif // !UNDEFINED_PRIORITY_CLASS

/// <summary>
/// Flags struct @ LDR_DATA_TABLE_ENTRY, ntdll.h
/// </summary>
typedef DWORD C_KERNEL_MODULE_FLAGS;

#define C_KERNEL_MODULE_FLAGS_PACKAGED_BINARY            (1UL << 0)
#define C_KERNEL_MODULE_FLAGS_MARKED_FOR_REMOVAL         (1UL << 1)
#define C_KERNEL_MODULE_FLAGS_IMAGE_DLL                  (1UL << 2)
#define C_KERNEL_MODULE_FLAGS_LOAD_NOTIFICATIONS_SENT    (1UL << 3)
#define C_KERNEL_MODULE_FLAGS_TELEMETRY_ENTRY_PROCESSED  (1UL << 4)
#define C_KERNEL_MODULE_FLAGS_PROCESS_STATIC_IMPORT      (1UL << 5)
#define C_KERNEL_MODULE_FLAGS_IN_LEGACY_LISTS            (1UL << 6)
#define C_KERNEL_MODULE_FLAGS_IN_INDEXES                 (1UL << 7)
#define C_KERNEL_MODULE_FLAGS_SHIM_DLL                   (1UL << 8)
#define C_KERNEL_MODULE_FLAGS_IN_EXCEPTION_TABLE         (1UL << 9)
#define C_KERNEL_MODULE_FLAGS_VERIFIER_PROVIDER          (1UL << 10) // 24H2
#define C_KERNEL_MODULE_FLAGS_SHIM_ENGINE_CALLOUT_SENT   (1UL << 11) // 24H2
#define C_KERNEL_MODULE_FLAGS_LOAD_IN_PROGRESS           (1UL << 12)
#define C_KERNEL_MODULE_FLAGS_LOAD_CONFIG_PROCESSED      (1UL << 13) // WIN10
#define C_KERNEL_MODULE_FLAGS_ENTRY_PROCESSED            (1UL << 14)
#define C_KERNEL_MODULE_FLAGS_PROTECT_DELAY_LOAD         (1UL << 15) // WINBLUE
#define C_KERNEL_MODULE_FLAGS_AUX_IAT_COPY_PRIVATE       (1UL << 16) // 24H2
#define C_KERNEL_MODULE_FLAGS_RESERVED_FLAGS3            (1UL << 17)
#define C_KERNEL_MODULE_FLAGS_DONT_CALL_FOR_THREADS      (1UL << 18)
#define C_KERNEL_MODULE_FLAGS_PROCESS_ATTACH_CALLED      (1UL << 19)
#define C_KERNEL_MODULE_FLAGS_PROCESS_ATTACH_FAILED      (1UL << 20)
#define C_KERNEL_MODULE_FLAGS_SCP_IN_EXCEPTION_TABLE     (1UL << 21)
#define C_KERNEL_MODULE_FLAGS_COR_IMAGE                  (1UL << 22)
#define C_KERNEL_MODULE_FLAGS_DONT_RELOCATE              (1UL << 23)
#define C_KERNEL_MODULE_FLAGS_COR_IL_ONLY                (1UL << 24)
#define C_KERNEL_MODULE_FLAGS_CHPE_IMAGE                 (1UL << 25)
#define C_KERNEL_MODULE_FLAGS_CHPE_EMULATOR_IMAGE        (1UL << 26) // WIN11
#define C_KERNEL_MODULE_FLAGS_RESERVED_FLAGS5            (1UL << 27)
#define C_KERNEL_MODULE_FLAGS_REDIRECTED                 (1UL << 28)
#define C_KERNEL_MODULE_FLAGS_RESERVED_FLAGS6            (3UL << 29)  // 2 bits (29-30)
#define C_KERNEL_MODULE_FLAGS_COMPAT_DATABASE_PROCESSED  (1UL << 31)

typedef enum _C_NATIVE_THREAD_BASEPRIORITY
{
	C_NATIVE_THREAD_BASEPRIORITY_IDLE = 0L,
	C_NATIVE_THREAD_BASEPRIORITY_LOWEST = 1L,
	C_NATIVE_THREAD_BASEPRIORITY_BELOW_NORMAL = 2L,
	C_NATIVE_THREAD_BASEPRIORITY_NORMAL = 8L,
	C_NATIVE_THREAD_BASEPRIORITY_ABOVE_NORMAL = 10L,
	C_NATIVE_THREAD_BASEPRIORITY_HIGHEST = 15L,
	C_NATIVE_THREAD_BASEPRIORITY_TIMECRITICAL = 31L,
	C_NATIVE_THREAD_BASEPRIORITY_UNKNOWN = 0xFF
} C_NATIVE_THREAD_BASEPRIORITY, * PC_NATIVE_THREAD_BASEPRIORITY;

/// <summary>
/// This is a specific structure for user object handles, not native handles.
/// <para> Native object handles, UCHAR ObjectTypeIndex @ OBJECT_TYPE_INFORMATION. </para>
/// <para> The ObjectTypeIndex may be subject to change accross Windows versions. </para>
/// </summary>
typedef enum _C_USER_HANDLE_OBJECT_TYPE
{
	C_USER_HANDLE_OBJECT_TYPE_UNKNOWN = 0u,
	C_USER_HANDLE_OBJECT_TYPE_PROCESS = 1u,
	C_USER_HANDLE_OBJECT_TYPE_THREAD = 2u,
	C_USER_HANDLE_OBJECT_TYPE_MUTANT = 3u,
	C_USER_HANDLE_OBJECT_TYPE_EVENT = 4u,
	C_USER_HANDLE_OBJECT_TYPE_SECTION = 5u,
	// BUGBUG WINBLUE 571662 2013-12-31 GenghisK: #ifdef this for OS after
	// WINBLUE
	C_USER_HANDLE_OBJECT_TYPE_SEMAPHORE = 6u
} C_USER_HANDLE_OBJECT_TYPE, * PC_USER_HANDLE_OBJECT_TYPE;

typedef enum C_ARCHITECTURE_TYPE
{
	C_ARCHITECTURE_TYPE_UNKNOWN = 0u,
	C_ARCHITECTURE_TYPE_X86 = 1u,
	C_ARCHITECTURE_TYPE_X64 = 2u
} C_ARCHITECTURE_TYPE, * PC_ARCHITECTURE_TYPE;

/// <summary>
/// MODULEENTRY32W, Tlhelp32.h data
/// <para> MODULEINFO, Psapi.h data </para>
/// <para> LDR_DATA_TABLE_ENTRY, ntdll.h data </para>
/// </summary>
typedef struct _C_MODULE_ENTRY
{
	/// <summary>
	/// LPVOID lpBaseOfDll @ MODULEINFO
	/// <para> PVOID DllBase @ LDR_DATA_TABLE_ENTRY </para>
	/// </summary>
	uintptr_t moduleLoadAddress;
	uintptr_t moduleEntryPoint;
	uintptr_t moduleBaseAddress;
	uintptr_t parentDllBaseAddress;
	SIZE_T moduleBaseSize;

	/// <summary>
	/// WCHAR szModule[MAX_MODULE_NAME32 + 1] @ MODULEENTRY32
	/// <para> UNICODE_STRING BaseDllName @ LDR_DATA_TABLE_ENTRY </para>
	/// </summary>
	const wchar_t* moduleName;

	/// <summary>
	/// WCHAR szExePath[MAX_PATH] @ MODULEENTRY32
	/// <para> UNICODE_STRING FullDllName @ LDR_DATA_TABLE_ENTRY </para>
	/// </summary>
	const wchar_t* modulePath;

	/// <summary>
	/// Use KernelModuleFlags structure for mapping
	/// </summary>
	DWORD kernelModuleFlags;
	DWORD moduleImageSize;
	DWORD processId;
	WORD tlsIndex;
} C_MODULE_ENTRY, * PC_MODULE_ENTRY;

/// <summary>
/// THREADENTRY32 @ Tlhelp32.h data
/// <para> SYSTEM_EXTENDED_THREAD_INFORMATION @ ntdll.h data </para>
/// </summary>
typedef struct _C_THREAD_ENTRY
{
	/// <summary>
	///  PVOID StartAddress @ SYSTEM_THREAD_INFORMATION
	/// </summary>
	uintptr_t kernelThreadStartAddress;

	/// <summary>
	///  PVOID Win32StartAddress @ SYSTEM_EXTENDED_THREAD_INFORMATION
	/// </summary>
	uintptr_t win32ThreadStartAddress;

	/// <summary>
	/// PVOID TebBaseAddress @ SYSTEM_EXTENDED_THREAD_INFORMATION
	/// </summary>
	uintptr_t tebBaseAddress;

	/// <summary>
	/// KPRIORITY BasePriority @ SYSTEM_THREAD_INFORMATION
	/// </summary>
	C_NATIVE_THREAD_BASEPRIORITY nativeThreadBasePriority;

	/// <summary>
	/// DWORD th32ThreadID @ THREADENTRY32
	/// <para> CLIENT_ID ClientId @ SYSTEM_THREAD_INFORMATION</para>
	/// </summary>
	DWORD threadId;
	DWORD threadOwnerProcessId;
} C_THREAD_ENTRY, * PC_THREAD_ENTRY;

/// <summary>
/// PSS_HANDLE_ENTRY @ processsnapshot.h data
/// <para> SYSTEM_HANDLE_TABLE_ENTRY_INFO @ ntdll.h data </para>
/// </summary>
typedef struct _C_HANDLE_ENTRY
{
	HANDLE handleValue;

	/// <summary>
	/// UNICODE_STRING TypeName @ OBJECT_TYPE_INFORMATION
	/// </summary>
	const wchar_t* typeName;
	const wchar_t* objectName;

	ACCESS_MASK grantedAccess;

	/// <summary>
	/// Based on <see cref="UserHandleObjectType"/>
	/// </summary>
	DWORD userTargetProcessId;

	/// <summary>
	/// PSS_OBJECT_TYPE ObjectType field @ PSS_HANDLE_ENTRY
	/// </summary>
	C_USER_HANDLE_OBJECT_TYPE userHandleObjectType;
} C_HANDLE_ENTRY, * PC_HANDLE_ENTRY;

/// <summary>
/// TOKEN_PRIVILEGES @ winnt.h data
/// <para> TOKEN_PRIVILEGES @ ntdll.h data </para>
/// </summary>
typedef struct _C_PRIVILEGE_ENTRY
{
	uint64_t TokenLuid;
	DWORD TokenAttributes;
} C_PRIVILEGE_ENTRY, * PC_PRIVILEGE_ENTRY;

/// <summary>
/// Data for process access token information.
/// <para> OpenProcessToken() @ Processthreadsapi.h </para>
/// <para> GetTokenInformation() @ Securitybaseapi.h </para>
/// <para> NtOpenProcessToken() @ ntdll.h </para>
/// <para> NtQueryInformationToken() @ ntdll.h </para>
/// </summary>
typedef struct _C_ACCESS_TOKEN
{
	/// <summary>
	/// Returns token attributes and tokenLuid's for each privilege held by the token.
	/// <para>Arg: TOKEN_INFORMATION_CLAS::TOKEN_PRIVILEGES </para>
	/// </summary>
	PC_PRIVILEGE_ENTRY TokenPrivileges;

	/// <summary>
		/// Arg: TOKEN_INFORMATION_CLAS::TOKEN_STATISTICS
		/// </summary>
	uint64_t TokenId{};

	/// <summary>
	/// Arg: TOKEN_INFORMATION_CLAS::TOKEN_STATISTICS
	/// </summary>
	uint64_t AuthenticationId{};

	/// <summary>
	/// Arg: TOKEN_INFORMATION_CLAS::TOKEN_STATISTICS
	/// </summary>
	DWORD SessionId;
} C_ACCESS_TOKEN, * PC_ACCESS_TOKEN;

/// <summary>
/// PROCESSENTRY32W @ Tlhelp32.h
/// <para> QueryFullProcessImageNameW @ WinBase.h </para>
/// <para> SYSTEM_PROCESS_INFORMATION @ ntdll.h </para>
/// <para> PROCESS_EXTENDED_BASIC_INFORMATION @ ntdll.h </para>
/// </summary>
typedef struct _C_PROCESS_ENTRY
{
	/// <summary>
	/// The file name of the executable image.
	/// <para> WCHAR szExeFile[MAX_PATH] @ PROCESSENTRY32W </para>
	/// <para> UNICODE_STRING ImageName @ SYSTEM_PROCESS_INFORMATION </para>
	/// </summary>
	const wchar_t* processName;

	/// <summary>
	/// LPWSTR lpExeName @ QueryFullProcessImageNameW()
	/// </summary>
	const wchar_t* userFullProcessImageName;

	/// <summary>
	/// UNICODE_STRING SystemInformation @ NtQueryInformationProcess()
	/// <para> Arg: PROCESSINFOCLASS::ProcessImageFileName (27) </para>
	/// </summary>
	const wchar_t* NativeImageFileName;
	uintptr_t pebBaseAddress;
	uintptr_t moduleBaseAddress;
	DWORD processId;
	DWORD parentProcessId;
	BOOL isProtectedProcess;

	/// <summary>
	/// Indicates that the process is 32-bit and runs under the WoW64 emulation.
	/// </summary>
	BOOL isWow64Process;

	/// <summary>
	/// The process belongs to a background job.
	/// </summary>
	BOOL isBackgroundProcess;

	/// <summary>
	/// The process runs in Isolated User Mode (IUM).
	/// </summary>
	BOOL isSecureProcess;

	/// <summary>
	/// The process is a Pico or a WSL process.
	/// </summary>
	BOOL isSubsystemProcess;
	BOOL hasVisibleWindow;
	C_ARCHITECTURE_TYPE architectureType;
} C_PROCESS_ENTRY, * PC_PROCESS_ENTRY;

typedef struct _C_PROCESS_OBJECT
{
	PC_MODULE_ENTRY moduleList;
	PC_THREAD_ENTRY threadList;
	PC_HANDLE_ENTRY handleList;
	C_PROCESS_ENTRY processEntry;
	C_ACCESS_TOKEN_ENTRY tokenList;
} C_PROCESS_OBJECT, * PC_PROCESS_OBJECT;

typedef struct _C_SYSTEM_OBJECT
{
	PC_PROCESS_OBJECT processList32;
	PC_PROCESS_OBJECT processListNt;
} C_SYSTEM_OBJECT, * PC_SYSTEM_OBJECT;

/* Use WindowsStructures.h for C++
#ifdef __cplusplus
}
#endif
*/
#endif // !CORVUS_WINDOWS_STRUCTURES_H_INCLUDED