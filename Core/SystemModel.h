#pragma once
#include "ProcessModel.h"

namespace Muninn::Model
{
	struct SystemModel
	{
		std::vector<ProcessModel> processList{};
	};
}