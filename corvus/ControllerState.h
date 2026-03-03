#pragma once
#include <stdint.h>

namespace Corvus::Controller
{
	enum class ProcessControllerState : uint8_t
	{
		Uninitialized,
		Initialized,
		Error,
		Disposed
	};
}