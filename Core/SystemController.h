#pragma once
#include "IController.h"

namespace Muninn::Controller
{
	class SystemController final : public IController
	{
	private:
		SystemController() = default;
		//Muninn::Model::SystemModel m_systemObject{};

	public:
		// Delete copy constructor and copy assignment operator
		SystemController(const SystemController&) = delete;
		SystemController& operator=(const SystemController&) = delete;
		~SystemController() = default;
		static SystemController& GetInstance() noexcept;
	};
}