<table>
  <tr>
    <td>
        <img width="200"
             src="https://github.com/user-attachments/assets/bddd2b09-5e16-44a1-ae18-0a92e5a0eb9a"
             alt="Corvus Banner" />
    </td>
    <td>
      <h1>Corvus</h1>
      <img src="https://custom-icon-badges.demolab.com/badge/Platform-Windows%2011-0078D6.svg?&logo=windows11&logoColor=white&style=for-the-badge" />
      <img src="https://img.shields.io/badge/Language-C%2B%2B%2020-00599C?logo=c%2B%2B&logoColor=white&style=for-the-badge" />
      <img src="https://img.shields.io/badge/Language-Legacy%20(MSVC)-A8B9CC?logo=c&logoColor=white&style=for-the-badge" />
      <img src="https://custom-icon-badges.demolab.com/badge/IDE-Visual%20Studio%202026-5C2D91.svg?&logo=visualstudio&logoColor=white&style=for-the-badge" />
      <img src="https://img.shields.io/badge/Snyk-Security%20Monitored-4C4A73?logo=snyk&logoColor=white&style=for-the-badge" />
    </td>
  </tr>
</table>

## Intro
Corvus is a Windows native SDK DLL (x86 / x64) written in ISO C++20 with a deliberately minimal, exceptionless C-style design.

It provides structured access to low-level Windows user-mode APIs, primarily:
- Win32
- Native NT (ntdll)

The project emphasizes architectural clarity, deterministic behavior, and explicit data modeling over convenience abstractions.
  
## Purpose
Corvus exposes Windows data: process, thread, module, handle, token, etc. information through a layered internal design.
It bridges raw native system calls and structured C++ data models without introducing hidden side effects or runtime magic.

The SDK is designed for:
- Process introspection
- Native structure mapping
- Handle and token analysis
- Architecture detection (x86 / x64 / WoW64)
- Low-level memory inspection (via `NtReadVirtualMemory` / `NtWriteVirtualMemory`)

As of now, it does **not** implement persistence mechanisms, obfuscation, or network behavior.

## Architecture
Corvus follows a layered MVC-inspired structure:

### DataProvisionLayer
Thin, explicit wrappers over Win32 and NT native calls.

These functions:
- Avoid hidden allocation patterns
- Avoid exceptions
- Prefer direct `NTSTATUS` / `BOOL` returns
- Expose buffer sizing explicitly where required

### DataTransferObjectLayer
Strongly defined data wrappers that unify structures across:
- ToolHelp32
- PSAPI
- Process Snapshot API
- Native NT structures

This layer normalizes disparate Windows APIs into coherent C++ structures while preserving native semantics.

### ControllerLayer
High-level orchestration classes that manage:
- Handle lifetime
- Object initialization & data population
- State tracking & state validation

Copy semantics are intentionally disabled to prevent unsafe handle duplication.

### ViewLayer
Contains raw user-interface-related utilities and WinUser helpers.
This layer is isolated from native process logic.

## Design Characteristics
- ISO C++20 (exceptionless style)
- Explicit resource ownership
- No hidden global state
- Minimal STL usage beyond containers and strings (C-style)
- Native NT structures preserved where meaningful
- Experimental NT structures are clearly marked `[[deprecated]]`
- Verbose naming convention
- Visual C++ XML documentation

## Build Requirements
Visual Studio (Desktop development with C++):
- MSVC x86 / x64 toolchain
- Windows 11 SDK
- ATL support (if enabled)
- vcpkg (optional)

## Namespace diagram
```mermaid
    graph TD

    %% External APIs
    Win32API[(Win32 API calls)]
    NtdllAPI[(Ntdll API calls)]

    %% Data Layer
    subgraph Data
        direction LR
        MemoryService
        WindowsProvider32
        WindowsProviderNt
    end

    %% API wiring
    Win32API --> WindowsProvider32
    NtdllAPI --> WindowsProviderNt

    %% Other layers
    subgraph Controller
        direction LR
        SystemController
        ProcessController
    end

    subgraph Object
        direction LR
        WindowsStructures
        C_WindowsStructures["C_WindowsStructures Legacy MSVC"]
        Math
    end

    subgraph View
        WinUserService
    end
```

## DataTransferObject diagram(s)
![Windows Structures](/WindowsStructures.png)
