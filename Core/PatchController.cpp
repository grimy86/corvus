#include "PatchController.h"
#undef NTSTATUS // Undefine the WindowsProvider32.h definition
#include <ntdef.h> // NTSTATUS codes

namespace Muninn::Controller
{
	bool PatchController::WritePatch(Muninn::Model::PatchModel& patchInfo) noexcept
	{
        // Invalid patchInfo guard
        if (!patchInfo.targetAddress || !patchInfo.size)
            return false;

        // Byte ownership guards
        if (!patchInfo.originalBytes &&
            patchInfo.byteOwnership == Muninn::Model::ByteOwnership::UserProvided)
            return false;

        // Internal ownership
        if (!patchInfo.originalBytes &&
            patchInfo.byteOwnership == Muninn::Model::ByteOwnership::Internal)
            patchInfo.originalBytes = new BYTE[patchInfo.size];

        NTSTATUS status{};
        switch (patchInfo.type)
        {
        case Muninn::Model::PatchType::Detour:
            status = DAL_Win32_WriteRelativeHook(
                patchInfo.targetAddress,
                patchInfo.hookAddress,
                patchInfo.size,
                patchInfo.originalBytes);
            break;

        case Muninn::Model::PatchType::Trampoline:
            // Trampoline hooks store the original bytes into the gateway
            status = DAL_Win32_WriteRelativeTrampolineHook(
                patchInfo.targetAddress,
                patchInfo.hookAddress,
                patchInfo.size,
                &patchInfo.gateway);
            break;

        case Muninn::Model::PatchType::Patch:
            status = DAL_Win32_PatchMemory(
                patchInfo.targetAddress,
                patchInfo.patchBytes,
                patchInfo.size,
                patchInfo.originalBytes);
            break;

        // Undefined PatchType
        default:
            status = STATUS_NOT_FOUND;
            break;
        }

        return NT_SUCCESS(status) ?
            true :
            false;
	}

    bool PatchController::RestorePatch(Muninn::Model::PatchModel& patchInfo) noexcept
    {
        // Invalid patchInfo guard
        if (!patchInfo.targetAddress || !patchInfo.size)
            return false;

        NTSTATUS status{};
        switch (patchInfo.type)
        {
        case Muninn::Model::PatchType::Detour:
            // No original bytes to restore
            if (!patchInfo.originalBytes)
                return false;

            status = DAL_Win32_PatchMemory(
                patchInfo.targetAddress,
                patchInfo.originalBytes,
                patchInfo.size,
                nullptr);
            break;

        case Muninn::Model::PatchType::Trampoline:
            status = DAL_Win32_RestoreRelativeTrampolineHook(
                patchInfo.targetAddress,
                patchInfo.gateway,
                patchInfo.size);
            break;

        case Muninn::Model::PatchType::Patch:
            // No original bytes to restore
            if (!patchInfo.originalBytes)
                return false;

            status = DAL_Win32_PatchMemory(
                patchInfo.targetAddress,
                patchInfo.originalBytes,
                patchInfo.size,
                nullptr);
            break;

        // Undefined PatchType
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
            m_state = PatchControllerState::DestructorError;

        m_state = PatchControllerState::Destructed;
    }
}