#pragma once
#include <math.h>

namespace Corvus::Object
{
	class Vector
	{
		float x{};
		float y{};
		float z{};

		float CalcAngleBetweenVectors(const Vector& vector) const;
		float VectorDotProduct(const Vector& vector) const;
		float CalcVectorLength() const;
		Vector ViewToVec() const;
		Vector VecToView() const;
		Vector operator-(const Vector& vector) const;
		float RadiansToDegrees(float rad) const;
		float DegreesToRadians(float deg) const;
	};
}