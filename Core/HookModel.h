#pragma once
#include <Windows.h>
#include <vector>

namespace Muninn::Model
{
	enum class HookState : uint8_t
	{
		Uninitialized,
		Enabled,
		Disabled
	};
	
	enum class HookType : uint8_t
	{
		/// <summary>
		/// Replaces target bytes with arbitrary shellcode,
		/// execution does not return to original.
		/// </summary>
		MemoryPatch,

		/// <summary>
		/// Overwrites target bytes with a REL32 JMP to a hook function,
		/// execution does not return to original.
		/// </summary>
		RelativeJump,

		/// <summary>
		/// Overwrites target bytes with a ABS64 JMP to a hook function
		/// (Only available on 64-bit builds.),
		/// execution does not return to original.
		/// </summary>
		AbsoluteJump,

		/// <summary>
		/// Overwrites target bytes with a JMP to a hook function,
		/// stolen bytes are preserved in a gateway so original
		/// can still be called.
		/// </summary>
		Trampoline,

		/// <summary>
		/// Overwrites a function pointer in an existing VTable with
		/// a hook function.
		/// </summary>
		VTableEntry,

		/// <summary>
		/// Replaces an object's VTable pointer (vptr) with a replacement
		/// VTable, allowing individual virtual functions to be redirected.
		/// </summary>
		VTableSwap,

		/// <summary>
		/// Replaces an entry in the Import Address Table (IAT) with
		/// a pointer to a hook function.
		/// </summary>
		IAT,
		EAT,
		VEH,
		HardwareBreakpoint
	};

	struct MemoryPatchModel
	{
		/// <summary>
		/// Buffer holding the patch bytes to write to the target address.
		/// </summary>
		std::vector<BYTE> patchBytes{};

		/// <summary>
		/// Buffer holding the original bytes before patching.
		/// </summary>
		std::vector<BYTE> originalBytes{};

		/// <summary>
		/// Target address in memory to patch. Must not be NULL.
		/// </summary>
		uintptr_t targetAddress{};

		/// <summary>
		/// Number of bytes affected by the patch.
		/// </summary>
		SIZE_T size{ 0 };
	};

	struct RelativeJumpModel
	{
		/// <summary>
		/// Buffer holding the original bytes before patching.
		/// </summary>
		std::vector<BYTE> OriginalBytes{};

		/// <summary>
		/// Target address in memory to patch. Must not be NULL.
		/// </summary>
		uintptr_t TargetAddress{};

		/// <summary>
		/// Address of the hook function to jump to. Must not be NULL.
		/// </summary>
		uintptr_t HookFunction{};

		/// <summary>
		/// Size of the patch in bytes. Must be at least 5 (JMP_REL32_LENGTH),
		/// instruction-aligned by caller.
		/// </summary>
		SIZE_T size{ 5 };
	};

	struct TrampolineModel
	{
		/// <summary>
		/// Target address in memory to patch. Must not be NULL.
		/// </summary>
		uintptr_t targetAddress{};

		/// <summary>
		/// Buffer holding the original bytes before patching. Fi
		/// </summary>
		uintptr_t gateway{};          // LPVOID returned by DAL, stored as uintptr_t

		/// <summary>
		/// Address of the hook function to jump to. Must not be NULL.
		/// </summary>
		uintptr_t hookFunction{};

		/// <summary>
		/// Size of the patch in bytes. Must be at least 5 (JMP_REL32_LENGTH),
		/// instruction-aligned by caller.
		/// </summary>
		SIZE_T size{ 5 };
	};














	struct RelativeJumpModel
	{
		// PatchSize = 5 minimum, but size is instruction-aligned at runtime
		std::vector<BYTE> OriginalBytes{};   // sized to Size before call, filled by DAL
		uintptr_t         TargetAddress{};
		uintptr_t         HookFunction{};
		SIZE_T            Size{ 5 };         // >= 5, instruction-aligned by caller
	};

	struct AbsoluteJumpModel
	{
		// PatchSize = 14 minimum, but size is instruction-aligned at runtime
		// DAL provides no originalBytes out-param — controller must save manually if needed
		std::vector<BYTE> OriginalBytes{};   // saved manually before DAL call if restoration needed
		uintptr_t         TargetAddress{};
		uintptr_t         HookFunction{};
		SIZE_T            Size{ 14 };        // >= 14, instruction-aligned by caller
	};

	struct TrampolineModel
	{
		// No OriginalBytes — restoration goes through Gateway via RestoreRelativeTrampolineHook
		uintptr_t Gateway{};          // LPVOID returned by DAL, stored as uintptr_t
		uintptr_t TargetAddress{};
		uintptr_t HookFunction{};
		SIZE_T    Size{ 5 };          // >= 5, instruction-aligned by caller
	};

	struct MemoryPatchModel
	{
		HookBase base{};

		/// <summary>
		/// Buffer holding the patch bytes to write to the target address.
		/// </summary>
		BYTE* patchBytes{ nullptr };

		/// <summary>
		/// Buffer holding the original bytes before patching.
		/// Used for restoration.
		/// </summary>
		BYTE* originalBytes{ nullptr };
	};

	struct RelativeJumpModel
	{
		static constexpr SIZE_T PatchSize = 5; // 0xE9 + rel32

		BYTE patchBytes[PatchSize]{ 0 };
		BYTE originalBytes[PatchSize]{ 0 };
		uintptr_t targetAddress{};
		uintptr_t hookFunction{};
	};

	struct AbsoluteJumpModel
	{
		// FF 25 00000000 = 6 bytes + 8-byte absolute address = 14 bytes
		static constexpr SIZE_T PatchSize = 14;
		 
		BYTE OriginalBytes[PatchSize]{ 0 };
		BYTE PatchBytes[PatchSize]{ 0 };
		uintptr_t targetAddress{};
		uintptr_t hookFunction{};
	};
}