#include "HookController.h"
#undef NTSTATUS // Undefine the WindowsProvider32.h definition
#include <ntdef.h> // NTSTATUS codes

namespace Muninn::Controller
{
	bool HookController::WriteHook(Muninn::Model::HookModel& hookInfo) noexcept
	{
        // Invalid hookInfo guard
        if (!hookInfo.targetAddress || !hookInfo.size)
            return false;

        // Byte ownership guards
        if (!hookInfo.originalBytes &&
            hookInfo.byteOwnership == Muninn::Model::ByteOwnership::UserProvided)
            return false;

        // Internal ownership
        if (!hookInfo.originalBytes &&
            hookInfo.byteOwnership == Muninn::Model::ByteOwnership::Internal)
            hookInfo.originalBytes = new BYTE[hookInfo.size];

        NTSTATUS status{};
        switch (hookInfo.type)
        {
        case Muninn::Model::HookType::Detour:
            status = DAL_Win32_WriteRelativeHook(
                hookInfo.targetAddress,
                hookInfo.hookAddress,
                hookInfo.size,
                patchInfo.originalBytes);
            break;

        case Muninn::Model::HookType::Trampoline:
            // Trampoline hooks store the original bytes into the gateway
            status = DAL_Win32_WriteRelativeTrampolineHook(
                patchInfo.targetAddress,
                patchInfo.hookAddress,
                patchInfo.size,
                &patchInfo.gateway);
            break;

        case Muninn::Model::HookType::Patch:
            status = DAL_Win32_PatchMemory(
                patchInfo.targetAddress,
                patchInfo.patchBytes,
                patchInfo.size,
                patchInfo.originalBytes);
            break;

        // Undefined HookType
        default:
            status = STATUS_NOT_FOUND;
            break;
        }

        return NT_SUCCESS(status) ?
            true :
            false;
	}

    bool PatchController::RestorePatch(Muninn::Model::HookModel& patchInfo) noexcept
    {
        // Invalid patchInfo guard
        if (!patchInfo.targetAddress || !patchInfo.size)
            return false;

        NTSTATUS status{};
        switch (patchInfo.type)
        {
        case Muninn::Model::HookType::Detour:
            // No original bytes to restore
            if (!patchInfo.originalBytes)
                return false;

            status = DAL_Win32_PatchMemory(
                patchInfo.targetAddress,
                patchInfo.originalBytes,
                patchInfo.size,
                nullptr);
            break;

        case Muninn::Model::HookType::Trampoline:
            status = DAL_Win32_RestoreRelativeTrampolineHook(
                patchInfo.targetAddress,
                patchInfo.gateway,
                patchInfo.size);
            break;

        case Muninn::Model::HookType::Patch:
            // No original bytes to restore
            if (!patchInfo.originalBytes)
                return false;

            status = DAL_Win32_PatchMemory(
                patchInfo.targetAddress,
                patchInfo.originalBytes,
                patchInfo.size,
                nullptr);
            break;

        // Undefined HookType
        default:
            status = STATUS_NOT_FOUND;
            break;
        }

        // Internal ownership cleanup
        if (patchInfo.byteOwnership == Muninn::Model::ByteOwnership::Internal)
        {
            delete[] patchInfo.originalBytes;
            patchInfo.originalBytes = nullptr;
        }

        return NT_SUCCESS(status) ?
            true :
            false;
    }

    PatchController::~PatchController() noexcept
    {
        if (!RestorePatch(m_patch))
            m_state = HookControllerState::DestructorError;

        m_state = HookControllerState::Destructed;
    }
}