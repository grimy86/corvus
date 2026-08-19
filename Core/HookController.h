#pragma once
#include "ControllerBase.h"
#include "HookModel.h"
#include <MuninnDal.h>

namespace Muninn::Controller
{
	class HookController final : public ControllerBase
	{
	private:
		Muninn::Model::HookType m_hook{};
		bool RestorePatch(Muninn::Model::HookModel& hInfo) noexcept;

	public:
		HookController() noexcept = default;
		HookController(const Muninn::Model::HookModel& patch) noexcept;

		// Restores detours, patches, etc.
		~HookController() noexcept;

		void SetPatchInfo(const Muninn::Model::HookModel& patchInfo) noexcept
		{
			m_patch = patchInfo;
		}

		const Muninn::Model::HookModel& GetPatchInfo() const noexcept
		{
			return m_patch;
		}

		bool WritePatch(Muninn::Model::HookModel& patchInfo) noexcept;
	};
}