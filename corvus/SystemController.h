#pragma once
#include "WindowsStructures.h"

namespace Corvus::Controller
{
	class SystemController final
	{
	private:
		SystemController() = default;
		Corvus::Object::SystemObject m_systemObject{};

	public:
		// Delete copy constructor and copy assignment operator
		SystemController(const SystemController&) = delete;
		SystemController& operator=(const SystemController&) = delete;
		~SystemController() = default;
		static SystemController& GetInstance() noexcept;

		BOOL UpdateProcessList32();
		BOOL UpdateProcessListNt();
	};
}