#pragma once
#include <MuninnDal.h>
#include "Offsets.h"

enum class PatchType
{
	Detour,      // Overwrites target bytes with a JMP to a hook function, execution does not return to original
	Trampoline,  // Overwrites target bytes with a JMP to a hook function, stolen bytes are preserved in a gateway so original can still be called
	Patch,       // Overwrites target bytes with arbitrary shellcode, no hook function involved
	VTable,      // Overwrites a single object instance's vtable pointer to redirect virtual function calls
	VTableInline,// Overwrites the vtable itself, affects all instances of the class
	IAT,         // Overwrites the import address table entry for a function, redirects all calls to an imported DLL function
	HWBP         // Uses x86 debug registers (DR0-DR3) to trigger an exception on access/execution, handled via VEH. Zero bytes written to target.
};

struct HookInfo
{
	LPVOID targetAddress;
	LPVOID hookAddress;
	LPVOID gateway;
	SIZE_T size;
	BYTE* originalBytes;
	BYTE* patchBytes;
	PatchType type = PatchType::Detour;
	BOOL ownsOriginalBytes = FALSE;
};

void InstallHook(HookInfo* hInfo);
void UninstallHook(HookInfo* hInfo);
void __cdecl DrawScoreDetour(DWORD* a1, int a2);
int __cdecl CEScanTrampoline();
void RecoilAssemblyHook(); // __declspec(naked)

inline HookInfo DrawScoreInfo =
{
	(LPVOID)(offsets::AssaultCube + offsets::drawScore),
	(LPVOID)DrawScoreDetour,
	nullptr,
	6,
	nullptr,
	nullptr
};

inline LPVOID ceScanGateway;
inline HookInfo ceScanTrampolineHookInfo =
{
	(LPVOID)(offsets::AssaultCube + offsets::ceScan),
	(LPVOID)CEScanTrampoline,
	ceScanGateway,
	6,
	nullptr,
	nullptr,
	PatchType::Trampoline
};

inline HookInfo shotDelayPatchInfo =
{
	(LPVOID)(offsets::AssaultCube + offsets::shotDelayInstruction),
	nullptr,
	nullptr,
	5,
	(BYTE*)"\x89\x0A\x8B\x76\x14",	// MOV [EDX], ECX | MOV ESI, [ESI+0x14]
	(BYTE*)"\x90\x90\x8B\x76\x14",	// NOP | NOP | MOV ESI, [ESI+0x14]
	PatchType::Patch
};

inline HookInfo kickBackMultiplierPatchInfo =
{
	(LPVOID)(offsets::AssaultCube + offsets::kickBackMultiplier),
	nullptr,
	nullptr,
	4,
	(BYTE*)"\xBC\x23\xD7\x0A",	// 0.0099999998f
	(BYTE*)"\x00\x00\x00\x00",	// 0.0f
	PatchType::Patch
};

inline HookInfo recoilAssemblyHookInfo =
{
	(LPVOID)(offsets::AssaultCube + offsets::recoilInstruction),
	(LPVOID)RecoilAssemblyHook,
	nullptr,
	7,
	nullptr,
	nullptr
};
inline uintptr_t recoilJumpBackAddress =
(uintptr_t)recoilAssemblyHookInfo.targetAddress + recoilAssemblyHookInfo.size;