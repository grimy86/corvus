#pragma once
#include "WindowsStructures.h"

namespace Muninn::Controller
{
	class SystemController final
	{
	private:
		SystemController() = default;
		Muninn::Object::SystemObject m_systemObject{};

	public:
		// Delete copy constructor and copy assignment operator
		SystemController(const SystemController&) = delete;
		SystemController& operator=(const SystemController&) = delete;
		~SystemController() = default;
		static SystemController& GetInstance() noexcept;
	};
}