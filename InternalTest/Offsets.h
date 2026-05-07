#pragma once
#include <stdint.h>
#include <windows.h>

// Basic types
struct vec3
{
	float x, y, z;
};

// External types
struct SDL_Surface;

// Function types
typedef void(__cdecl* SDL_WM_SetCaption_t)(const char* title, const char* icon);
typedef SDL_Surface*(__cdecl* IMG_Load_t)(const char* file);
typedef void(__cdecl* SDL_WM_SetIcon_t)(SDL_Surface* icon, uint8_t* mask);
typedef int(__cdecl* CEScan_t)();
typedef void(__cdecl* CameraMatrixSetup_t)();
typedef void(__cdecl* DrawScore_t)(DWORD* a1, int a2);
typedef int(__cdecl* ShowMenu_t)(char a1);
typedef int(__cdecl* PlayerHover_t)();
typedef void(__cdecl* DrawHud_t)(int, int, int, char);
typedef void(__cdecl* Sub_41EB50_t)(int a1);

// Global offsets
namespace offsets
{	
	// Base modules
	inline uintptr_t AssaultCube = 0x400000;
	inline uintptr_t SDL = 0x68100000;

	// .text
	inline uintptr_t CameraMatrixSetup = 0x4080;
	inline uintptr_t blendBox = 0x4B30;
	inline uintptr_t ceScan = 0x51D0;
	inline uintptr_t drawHud = 0xAAF0;
	inline uintptr_t measureStringSize = 0x19F00;
	inline uintptr_t renderText = 0x1A150;
	inline uintptr_t sub_41EB50 = 0x1EB50;
	inline uintptr_t showMenu = 0x5CBB0;
	inline uintptr_t drawScore = 0x5D990;
	inline uintptr_t playerHover = 0x607C0;
	inline uintptr_t recoilInstruction = 0x62274;
	inline uintptr_t shotDelayInstruction = 0x637E4;
	inline uintptr_t sdl_WM_SetCaption = 0x9E58C;
	inline uintptr_t img_Load = 0x9E5B6;
	inline uintptr_t _invoke_watson = 0xBC5E2;
	inline uintptr_t __report_gsfailure = 0xC6FD1;
	inline uintptr_t sdl_WM_SetIcon = 0x2B110; // SDL.dll

	// .data
	inline uintptr_t windowTitle{ 0xEC478 }; // char[16]
	inline uintptr_t kickBackMultiplier{ 0xEE3F8 }; // float*
	inline uintptr_t currentFPS{ 0x100378 }; // float*
	inline uintptr_t sdlVirtualWidth{ 0x102574 }; // int*
	inline uintptr_t glEnum{ 0x109D2C }; // glEnum*
	inline uintptr_t currentMenu{ 0x10A2D4 }; // int*
	inline uintptr_t localPlayer = 0x10F4F4; // Player**
	inline uintptr_t antiCheatLocalPlayer = 0x109B74; // Player**
	inline uintptr_t isDebuggerPresent = 0x101610; // int*
	inline uintptr_t entityList = 0x10F4F8; // Player[32]
	inline uintptr_t playerCount = 0x10F500; // int*
	inline uintptr_t gameTimer = 0x109EB0; // int*
	inline uintptr_t mapName = 0x109EC0; // char[16]
	inline uintptr_t gameModeIndex = 0x10F49C; // int*
	inline uintptr_t localPlayer2 = 0x11E20C; // Player**
	inline uintptr_t formattedGameString = 0x12C8C0; // char[64]

	// .rsrc
	inline uintptr_t RT_ICON_3 = 0x12E1BC; // char[4392]
}

// Structures
#pragma pack(push, 1)
struct WeaponInfo
{
	char pad0[0x120];  // 0x00 → 0x120
	float mirrored;    // 0x120 → 0x124
	float recoil;      // 0x124 → 0x128
};

struct Weapon
{
	char pad0[0xC];        // 0x00 → 0x0C
	WeaponInfo* info;      // 0x0C → 0x10 (4 bytes)
	char pad1[0x14 - 0x10]; // 0x10 → 0x14
	int ammo;              // 0x14
};

struct Player
{
	char pad0[0x10];
	vec3 velocity;          // 0x10
	char pad1[0x24 - 0x1C];
	int jumpRelated;        // 0x24
	vec3 camera;            // 0x28
	vec3 position;          // 0x34
	vec3 viewAngles;        // 0x40
	char pad2[0x82 - 0x4C];
	uint8_t gameModeFlag;       // 0x82
	uint8_t gameModeVisibility; // 0x83
	char pad3[0xF8 - 0x84];
	int health;             // 0xF8
	int armor;              // 0xFC
	char pad4[0x158 - 0x100];
	int grenadeAmmo;        // 0x158
	char pad5[0x180 - 0x15C];
	int grenadeAnimation;   // 0x180
	char pad6[0x1A8 - 0x184];
	int grenadesThrown;     // 0x1A8
	char pad7[0x224 - 0x1AC];
	uint8_t isShooting;     // 0x224
	char name[64];          // 0x225
	char pad8[0x32C - 0x265];
	int team;               // 0x32C
	char pad9[0x338 - 0x330];
	uint8_t spectatorFlag;  // 0x338
	char pad10[0x374 - 0x339];
	uintptr_t weaponPtr;    // 0x374
};
#pragma pack(pop)