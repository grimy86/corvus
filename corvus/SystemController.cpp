#include "SystemController.h"

namespace Muninn::Controller
{
	SystemController& SystemController::GetInstance() noexcept
	{
		static SystemController instance;
		return instance;
	}
}