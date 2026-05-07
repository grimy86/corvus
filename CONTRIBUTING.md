# Contributing to Muninn
Thank you for your interest in contributing to Muninn.

## Architecture Overview
Muninn is structured into architectural layers:
- DAL: Direct interaction with APIs or others in order to read/write/execute data.
- ControllerLayer: High-level orchestration/abstraction of DAL functionality.
- ViewLayer
- ModelLayer

## Minimal Build Requirements
- Visual Studio (MSVC)
- Windows SDK (latest)

Build steps:
1. Clone repository
2. Open solution file
3. Build in Debug & Release (x86 & x64)

## Code Guidelines
### General Rules
- Use explicit and appropriate Windows types (DWORD, uintptr_t, HANDLE)
- Avoid implicit type narrowing or platform-dependent assumptions
- Prefer NTSTATUS return types in DAL functions for detailed error reporting
- Keep DAL functions stateless where possible (what does this even mean ?)

### Memory Management
- DAL must clearly define ownership of returned memory
- If memory is allocated in DAL, ownership must be documented:
  - caller frees OR
  - caller receives view-only buffer OR
  - RAII wrapper is used

- Prefer RAII wrappers in CORE and above
- All HANDLEs must be explicitly closed or transferred with ownership

### Naming Conventions
- DAL functions: DAL_<FunctionName><APISuffix>
- CORE C++ functions: use namespaces (Muninn::ControllerLayer, etc.)
- Do not rename existing code without discussion
- Naming changes must be proposed via issue or discussion

## API Stability
Muninn is under active development.
- Breaking changes may occur, please test yourself before requesting a pull
- Existing functions may be refactored
- Internal structures are not guaranteed stable

## Pull Requests
All PRs should:
- Have a single responsibility
- Include a clear description of changes
- Not mix refactoring and feature changes
- Compile successfully on x64 Debug and Release

## Testing
- Include reproduction steps where applicable
- Validate changes in both Debug and Release builds
- Ensure DAL functionality is not broken by changes

## Scope
This project is focused on:
- Windows internals
- Process and memory manipulation
- Reverse engineering tooling

Out of scope:
- Cross-platform support
- User-mode application frameworks
- UI design systems

## Code Style
- Clear separation between declarations and logic
- No global mutable state unless explicitly required
- Prefer explicit types over auto
- Keep DAL functions stateless
