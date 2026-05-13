#pragma once
#include "IController.h"
#include "PatchModel.h"
#include <MuninnDal.h>

namespace Muninn::Controller
{
	/// <summary>
	/// A state machine for tracking the lifecycle of the patch controller itself.
	/// </summary>
	enum class PatchControllerState : uint8_t
	{
		None,
		Constructed,
		ConstructorError,
		Disposed,
		DisposeError,
		Destructed,
		DestructorError
	};

	class PatchController final : public IController
	{
	private:
		PatchControllerState m_state{ PatchControllerState::None };
		Muninn::Model::PatchModel m_patch{};
		bool RestorePatch(Muninn::Model::PatchModel& hInfo) noexcept;

	public:
		PatchController() noexcept = default;
		PatchController(const Muninn::Model::PatchModel& patch) noexcept;

		// Restores detours, patches, etc.
		~PatchController() noexcept;

		void SetPatchInfo(const Muninn::Model::PatchModel& patchInfo) noexcept
		{
			m_patch = patchInfo;
		}

		const Muninn::Model::PatchModel& GetPatchInfo() const noexcept
		{
			return m_patch;
		}

		bool WritePatch(Muninn::Model::PatchModel& patchInfo) noexcept;
	};
}