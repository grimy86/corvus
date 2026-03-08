#pragma once
#include <math.h>

namespace Muninn::Object
{
	class Vector final
	{
	public:
		float x{};
		float y{};
		float z{};

		Vector operator-(const Vector& vector) const;

		Vector ViewToVec() const;
		Vector VecToView() const;
		float CalcAngleBetweenVectors(const Vector& vector) const;
		float VectorDotProduct(const Vector& vector) const;
		float CalcVectorLength() const;
		float RadiansToDegrees(float radians) const;
		float DegreesToRadians(float degrees) const;
	};
}