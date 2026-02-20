#pragma once
#include <math.h>

namespace Corvus::Math
{
	class Vector
	{
	public:
		float x{};
		float y{};
		float z{};

		float CalcAngleBetweenVectors(const Vector& vector) const;
		float VectorDotProduct(const Vector& vector) const;
		float CalcVectorLength() const;
		Vector ViewToVec() const;
		Vector VecToView() const;
		Vector operator-(const Vector& vector) const;
	};

	float RadiansToDegrees(float rad);
	float DegreesToRadians(float deg);
}