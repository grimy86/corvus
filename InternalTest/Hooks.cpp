#include "Offsets.h"
#include "Hooks.h"
#include <cstdio>
#include <MuninnDal.h>

void InstallHook(HookInfo* hInfo)
{
    if (!hInfo || !hInfo->targetAddress || !hInfo->size)
    {
        printf("InstallHook: invalid HookInfo.\n");
        return;
    }

	// Save original bytes if not already saved
    if (!hInfo->originalBytes)
    {
        hInfo->originalBytes = new BYTE[hInfo->size];
        memcpy(hInfo->originalBytes,
            hInfo->targetAddress,
            hInfo->size);
        hInfo->ownsOriginalBytes = TRUE;
    }

    switch (hInfo->type)
    {
    case PatchType::Patch:
        DAL_PatchMemory32(
            hInfo->targetAddress,
            hInfo->patchBytes,
            hInfo->size);
        break;

    case PatchType::Trampoline:
        DAL_WriteRelativeTrampoline32(
            hInfo->targetAddress,
            hInfo->hookAddress,
            hInfo->size,
            &hInfo->gateway);
        break;

    case PatchType::Detour:
        DAL_WriteRelativeDetour32(
            hInfo->targetAddress,
            hInfo->hookAddress,
            hInfo->size);
        break;

    default:
        printf("InstallHook: unknown HookType.\n");
        break;
    }
}

void UninstallHook(HookInfo* hInfo)
{
    if (!hInfo || !hInfo->targetAddress || !hInfo->size)
    {
        printf("UninstallHook: invalid HookInfo.\n");
        return;
    }

    switch (hInfo->type)
    {
    case PatchType::Trampoline:
        DAL_RestoreRelativeTrampoline32(
            hInfo->targetAddress,
            hInfo->gateway,
            hInfo->size);
        break;

    case PatchType::Patch:
    case PatchType::Detour:
        if (!hInfo->originalBytes)
        {
            printf("UninstallHook: originalBytes is nullptr, cannot restore.\n");
            return;
        }

        DAL_PatchMemory32(
            hInfo->targetAddress,
            hInfo->originalBytes,
            hInfo->size);

        if (hInfo->ownsOriginalBytes)
        {
            delete[] hInfo->originalBytes;
            hInfo->originalBytes = nullptr;
            hInfo->ownsOriginalBytes = FALSE;
        }
        break;

    default:
        printf("UninstallHook: unknown HookType.\n");
        break;
    }
}

// Removes the hook temporarily
void InlineHook(HookInfo* hInfo)
{
    DWORD pageProtection{};
    VirtualProtect(
        hInfo->targetAddress,
        hInfo->size,
        PAGE_EXECUTE_READWRITE,
        &pageProtection);

    memcpy(
        hInfo->targetAddress,
        hInfo->originalBytes,
        hInfo->size);

    VirtualProtect(
        hInfo->targetAddress,
        hInfo->size,
        pageProtection,
        &pageProtection);
}

void __cdecl DrawScoreDetour(DWORD* a1, int a2)
{
    InlineHook(&DrawScoreInfo);

    // Call original function
    DrawScore_t DrawScore =
        (DrawScore_t)DrawScoreInfo.targetAddress;

    DrawScore(a1, a2);

    // Reinstall hook
    DAL_WriteRelativeDetour32(
        DrawScoreInfo.targetAddress,
        DrawScoreInfo.hookAddress,
        DrawScoreInfo.size);

    // Change the game string
    char* formattedGameString =
        (char*)(offsets::AssaultCube + 
            offsets::formattedGameString);

    strcpy_s(
        formattedGameString,
        64,
        "The C++ Detour works!");

    // Get fly hack
    Player* localPlayer =
        *(Player**)(offsets::AssaultCube +
            offsets::localPlayer);

    if (localPlayer)
        localPlayer->spectatorFlag = 5;

    // Console output
    HANDLE console = GetStdHandle(STD_OUTPUT_HANDLE);
    COORD pos{
        0,
        2
    };
    SetConsoleCursorPosition(console, pos);
    static int count = 0;
    int gameTimer = *(int*)(offsets::AssaultCube + offsets::gameTimer);
    printf("DrawScoreHook: count[%i], gameTimer[%i]\r", ++count, gameTimer);
}

int __cdecl CEScanTrampoline()
{
    // Console output
    HANDLE console = GetStdHandle(STD_OUTPUT_HANDLE);
    COORD pos{
        0,
        3
    };
    SetConsoleCursorPosition(console, pos);
    static int count = 0;
    int gameTimer = *(int*)(offsets::AssaultCube + offsets::gameTimer);
    printf("CEScanHook: count[%i], gameTimer[%i]\r", ++count, gameTimer);
    return ((CEScan_t)ceScanTrampolineHookInfo.gateway)();
}

void __declspec(naked) RecoilAssemblyHook()
{
    __asm
    {
        push eax
        mov eax, 0x50F4F4
        mov eax, [eax]              // player*
        mov ecx, [eax + 0x374]      // weapon*
        mov edx, [ecx + 0x14]       // ammo*
        mov dword ptr[edx], 0x53A   // 1337

        mov ecx, eax                // player*
        add ecx, 0xF8               // healthOffset
        mov dword ptr[ecx], 0x539   // 1337
        add ecx, 0x4                // ammoOffset
        mov dword ptr[ecx], 0x539   // 1337
        pop eax

        mov word ptr[edi + 0x122], 0x0
        movsx ecx, word ptr[edi + 0x122]
        jmp dword ptr[recoilJumpBackAddress]
    }
}