#include <MuninnDal.h>
#include "Offsets.h"
#include "Hooks.h"
#include <cstdio>

const char* iconFilePath{ "C:\\Program Files (x86)\\AssaultCube\\packages\\crosshairs\\cube.png" };

DWORD WINAPI TestThread(HMODULE libModule)
{
	MessageBoxA(nullptr, "DLL injected successfully!", "Info", MB_OK | MB_ICONINFORMATION);

    // Allocating console for debugging
    AllocConsole();
    FILE* f;
    freopen_s(&f, "CONOUT$", "w", stdout);
    
    // Initializing function pointers
    SDL_WM_SetCaption_t SDL_WM_SetCaption =
        (SDL_WM_SetCaption_t)(offsets::AssaultCube + offsets::sdl_WM_SetCaption);

    IMG_Load_t IMG_Load =
        (IMG_Load_t)(offsets::AssaultCube + offsets::img_Load);

    SDL_WM_SetIcon_t SDL_WM_SetIcon =
        (SDL_WM_SetIcon_t)(offsets::SDL + offsets::sdl_WM_SetIcon);

    // Calling base module functions
    SDL_WM_SetCaption("Calling game functions!", nullptr);
    printf("Called SDL_WM_SetCaption\n");
    SDL_Surface* iconSurface{ IMG_Load(iconFilePath) };
    if (iconSurface == nullptr)
    {
        printf("Failed to load icon.png\n");
        FreeLibraryAndExitThread(libModule, 1);
        return 1;
    }

	// Calling loaded module functions
    SDL_WM_SetIcon(iconSurface, nullptr);
    printf("Called SDL_WM_SetIcon\n");

    // Install regular C++ hook
    InstallHook(&DrawScoreInfo);

	// Install trampoline hook
    InstallHook(&ceScanTrampolineHookInfo);

    // Install assembly hook
    InstallHook(&recoilAssemblyHookInfo);

    // Install shellcode patches
    InstallHook(&shotDelayPatchInfo);
    InstallHook(&kickBackMultiplierPatchInfo);

    // Keep DLL alive until END key is pressed
    while (!GetAsyncKeyState(VK_END))
    {
        Sleep(100);
    }

    UninstallHook(&DrawScoreInfo);
    UninstallHook(&ceScanTrampolineHookInfo);
    UninstallHook(&recoilAssemblyHookInfo);
    UninstallHook(&shotDelayPatchInfo);
    UninstallHook(&kickBackMultiplierPatchInfo);

    HWND consoleWindow = GetConsoleWindow();
    FreeConsole();
    PostMessage(consoleWindow, WM_CLOSE, 0, 0);
    FreeLibraryAndExitThread(libModule, 0);
    return 0;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        DisableThreadLibraryCalls(hModule);

        HANDLE hThread{ CreateThread(
                    nullptr,
                    0,
                    (LPTHREAD_START_ROUTINE)TestThread,
                    hModule,
                    0,
                    nullptr) };

        if (hThread)
            CloseHandle(hThread);

        break;
    }

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }

    return TRUE;
}