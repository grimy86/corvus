#pragma once
#include <Windows.h>
#include <string>

namespace Muninn::Model
{
    enum class InjectionTechnique : uint8_t
    {
        Unknown,
        LoadLib,
        ManualMap,
        Reflective,
    };

    enum class InjectionVector : uint8_t
    {
        Unknown,
        CreateRemoteThread,
        NtCreateThreadEx,
        QueueUserAPC,
        SetWinHookEx,
    };

    enum class InjectionState : uint8_t
    {
        Unknown,
        Success,
        AllocFailed,
        WriteFailed,
        ThreadFailed,
        EjectFailed,
    };

    struct InjectorModel
    {
        uintptr_t          RemoteModuleBase{ 0 };   // base address in target process
        HANDLE             InjectionThreadHandle{ nullptr };
        InjectionTechnique Technique{ InjectionTechnique::LoadLib };
        InjectionVector    Vector{ InjectionVector::CreateRemoteThread };
        InjectionState    Result{ InjectionState::Unknown };
        bool               IsInjected{ false };
        std::wstring       DllPath{};
    };
}