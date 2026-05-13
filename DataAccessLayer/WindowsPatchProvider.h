#ifndef WINDOWS_PATCH_PROVIDER_H
#define WINDOWS_PATCH_PROVIDER_H

#include "MuninnConfig.h"

#ifndef NTSTATUS
#define NTSTATUS LONG
#endif // !NTSTATUS

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_WriteVirtualMemory(
	HANDLE processHandle,
	uintptr_t address,
	const void* value,
	SIZE_T size);

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_WriteVirtualMemory(
	_In_ const HANDLE processHandle,
	_In_ const uintptr_t address,
	_In_ const void* const value,
	_In_ const SIZE_T size);

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_ReadVirtualMemory(
	HANDLE processHandle,
	uintptr_t address,
	void* out,
	SIZE_T size);

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_ReadVirtualMemory(
	_In_ const HANDLE processHandle,
	_In_ const uintptr_t address,
	_Out_ void* const out,
	_In_ const SIZE_T size);

/// <summary>
/// Patches a region of memory with arbitrary bytes, optionally saving the original bytes first.
/// Temporarily elevates page protection to PAGE_EXECUTE_READWRITE for the duration of the write.
/// </summary>
/// <param name="targetAddress">Address in memory to patch. Must not be NULL.</param>
/// <param name="patchBytes">Buffer containing the bytes to write. Must not be NULL.</param>
/// <param name="size">Number of bytes to write. Must be greater than zero.</param>
/// <param name="originalBytes">Optional buffer to receive the original bytes before patching.
/// Caller must ensure buffer is at least <paramref name="size"/> bytes. Pass NULL to skip.</param>
/// <returns>
/// STATUS_SUCCESS on success.
/// STATUS_INVALID_PARAMETER_1 if targetAddress is NULL.
/// STATUS_INVALID_PARAMETER_2 if patchBytes is NULL.
/// STATUS_INVALID_PARAMETER_3 if size is zero.
/// STATUS_UNSUCCESSFUL if VirtualProtect fails.
/// </returns>
MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_PatchMemory(
	_In_ LPVOID const targetAddress,
	_In_ const BYTE* const patchBytes,
	_In_ const SIZE_T size,
	_Out_opt_ BYTE* originalBytes);

/// <summary>
/// Writes a relative 32-bit JMP detour (E9 xx xx xx xx) at the target address.
/// Remaining bytes up to <paramref name="size"/> are padded with NOPs.
/// Execution does not return to the original function.
/// </summary>
/// <param name="targetAddress">Address to overwrite with the JMP. Must not be NULL.</param>
/// <param name="detourAddress">Address of the hook function to jump to. Must not be NULL.</param>
/// <param name="size">Number of bytes to overwrite. Must be at least 5 (JMP_REL32_LENGTH).</param>
/// <param name="originalBytes">Optional buffer to receive the original bytes before patching.
/// Caller must ensure buffer is at least <paramref name="size"/> bytes. Pass NULL to skip.</param>
/// <returns>
/// STATUS_SUCCESS on success.
/// STATUS_INVALID_PARAMETER_1 if targetAddress is NULL.
/// STATUS_INVALID_PARAMETER_2 if detourAddress is NULL.
/// STATUS_INVALID_PARAMETER_3 if size is less than JMP_REL32_LENGTH.
/// STATUS_NOT_SUPPORTED if the relative offset exceeds the ±2GB rel32 range.
/// STATUS_UNSUCCESSFUL if the underlying memory patch fails.
/// </returns>
MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_WriteRelativeHook(
	_In_ LPVOID const targetAddress,
	_In_ LPVOID const detourAddress,
	_In_ const SIZE_T size,
	_Out_opt_ BYTE* originalBytes);

/// <summary>
/// Writes a relative 32-bit JMP trampoline at the target address.
/// Stolen bytes are preserved in an executable gateway buffer, followed by a JMP back,
/// allowing the original function to still be called through the gateway.
/// </summary>
/// <param name="targetAddress">Address to overwrite with the JMP. Must not be NULL.</param>
/// <param name="detourAddress">Address of the hook function to jump to. Must not be NULL.</param>
/// <param name="size">Number of bytes to steal. Must be at least 5 (JMP_REL32_LENGTH).</param>
/// <param name="pGatewayOut">Receives a pointer to the allocated gateway buffer.
/// Caller is responsible for freeing via DAL_Win32_RestoreRelativeTrampolineHook. Must not be NULL.</param>
/// <returns>
/// STATUS_SUCCESS on success.
/// STATUS_INVALID_PARAMETER_1 if targetAddress is NULL.
/// STATUS_INVALID_PARAMETER_2 if detourAddress is NULL.
/// STATUS_INVALID_PARAMETER_3 if size is less than JMP_REL32_LENGTH.
/// STATUS_INVALID_PARAMETER_4 if pGatewayOut is NULL.
/// STATUS_NO_MEMORY if gateway allocation fails.
/// STATUS_NOT_SUPPORTED if either relative offset exceeds the ±2GB rel32 range.
/// </returns>
MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_WriteRelativeTrampolineHook(
	_In_  LPVOID const targetAddress,
	_In_  LPVOID const detourAddress,
	_In_  SIZE_T const size,
	_Out_ LPVOID* const pGatewayOut);

/// <summary>
/// Restores the original bytes at the target address from the gateway buffer,
/// then frees the gateway. Pair this with DAL_Win32_WriteRelativeTrampolineHook.
/// </summary>
/// <param name="targetAddress">Address that was originally patched. Must not be NULL.</param>
/// <param name="gatewayAddress">Gateway buffer returned by DAL_Win32_WriteRelativeTrampolineHook. Must not be NULL.</param>
/// <param name="size">Number of bytes to restore. Must be at least 5 (JMP_REL32_LENGTH).</param>
/// <returns>
/// STATUS_SUCCESS on success.
/// STATUS_INVALID_PARAMETER_1 if targetAddress is NULL.
/// STATUS_INVALID_PARAMETER_2 if gatewayAddress is NULL.
/// STATUS_INVALID_PARAMETER_3 if size is less than JMP_REL32_LENGTH.
/// STATUS_UNSUCCESSFUL if restoration or gateway deallocation fails.
/// </returns>
MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_RestoreRelativeTrampolineHook(
	_In_ LPVOID const targetAddress,
	_In_ LPVOID const gatewayAddress,
	_In_ SIZE_T const size);

/// <summary>
/// Writes an absolute 64-bit JMP detour (FF 25 00000000 + 8-byte address) at the target address.
/// Only available on 64-bit builds. Remaining bytes up to <paramref name="size"/> are padded with NOPs.
/// </summary>
/// <param name="targetAddress">Address to overwrite with the JMP. Must not be NULL.</param>
/// <param name="detourAddress">Absolute 64-bit address to jump to. Upper 16 bits must be zero (canonical user-space address).</param>
/// <param name="size">Number of bytes to overwrite. Must be at least 14 (JMP_ABS64_LENGTH).</param>
/// <returns>
/// STATUS_SUCCESS on success.
/// STATUS_NOT_IMPLEMENTED on 32-bit builds.
/// STATUS_INVALID_PARAMETER_1 if targetAddress is NULL.
/// STATUS_INVALID_PARAMETER_2 if detourAddress is not a canonical user-space address.
/// STATUS_INVALID_PARAMETER_3 if size is less than JMP_ABS64_LENGTH.
/// STATUS_UNSUCCESSFUL if the underlying memory patch fails.
/// </returns>
MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_WriteAbsoluteHook(
	_In_ LPVOID const targetAddress,
	_In_ LPVOID const detourAddress,
	_In_ const SIZE_T size);

/// <returns>
/// STATUS_NOT_IMPLEMENTED
/// </returns>
MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_WriteVTableHook(
	_In_  LPVOID const  pObject,
	_In_  DWORD const   methodIndex,
	_In_  LPVOID const  hookAddress,
	_Out_ LPVOID* const pOriginalOut);

/// <returns>
/// STATUS_NOT_IMPLEMENTED
/// </returns>
MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_RestoreVTableHook(
	_In_ LPVOID const pObject,
	_In_ DWORD const  methodIndex,
	_In_ LPVOID const originalAddress);

/// <returns>
/// STATUS_NOT_IMPLEMENTED
/// </returns>
MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_WriteInlineVTableHook(
	_In_  LPVOID const  vTableAddress,
	_In_  DWORD const   methodIndex,
	_In_  LPVOID const  hookAddress,
	_Out_ LPVOID* const pOriginalOut);

/// <returns>
/// STATUS_NOT_IMPLEMENTED
/// </returns>
MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_RestoreInlineVTableHook(
	_In_ LPVOID const vTableAddress,
	_In_ DWORD const methodIndex,
	_In_ LPVOID const originalAddress);

/// <returns>
/// STATUS_NOT_IMPLEMENTED
/// </returns>
MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_WriteIATHook(
	_In_  const WCHAR* const moduleName,
	_In_  const WCHAR* const functionName,
	_In_  LPVOID const hookAddress,
	_Out_ LPVOID* const pOriginalOut);

/// <returns>
/// STATUS_NOT_IMPLEMENTED
/// </returns>
MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_RestoreIATHook(
	_In_ LPCWSTR const moduleName,
	_In_ LPCWSTR const functionName,
	_In_ LPVOID const originalAddress);

// SOFTWARE BREAKPOINT HOOKING?

/// <returns>
/// STATUS_NOT_IMPLEMENTED
/// </returns>
MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_WriteHWBPHook(
	_In_ LPVOID const targetAddress,
	_In_ DWORD const condition,
	_In_ PVECTORED_EXCEPTION_HANDLER const veHandler);

/// <returns>
/// STATUS_NOT_IMPLEMENTED
/// </returns>
MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_RestoreHWBPHook(
	_In_ LPVOID const targetAddress,
	_In_ PVECTORED_EXCEPTION_HANDLER const veHandler);

#endif // !WINDOWS_PATCH_PROVIDER_H