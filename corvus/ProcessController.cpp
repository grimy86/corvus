#include "ProcessController.h"

namespace Corvus::Controller
{
	ProcessController& ProcessController::GetInstance() noexcept
	{
		static ProcessController instance;
		return instance;
	}
}