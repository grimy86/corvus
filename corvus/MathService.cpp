#include "MathService.h"

namespace Corvus::Math
{
	float Vector::CalcAngleBetweenVectors(const Vector& vector) const
	{
		return RadiansToDegrees(acos(VectorDotProduct(vector) / (CalcVectorLength() * vector.CalcVectorLength())));
	}

	Vector Vector::ViewToVec() const
	{
		// x = yaw
		// y = pitch

		Vector viewVector{};
		if (x >= 0.0f && x < 90.0f) // +x, -y
		{
			viewVector.y = -1.0f;
			viewVector.x = tan(DegreesToRadians(x));

		}
		else if (x >= 90.0f && x < 180.0f) // +x, +y
		{
			viewVector.x = 1.0f;
			viewVector.y = tan(DegreesToRadians(x - 90.0f));
		}
		else if (x >= 180.0f && x < 270.0f) // -x, +y
		{
			viewVector.y = 1.0f;
			viewVector.x = -tan(DegreesToRadians(x - 180.0f));
		}
		else // -x, -y
		{
			viewVector.x = -1.0f;
			viewVector.y = -tan(DegreesToRadians(x - 270.0f));
		}

		//Pitch angles
		if (y >= 0.0f)
		{
			viewVector.z = tan(DegreesToRadians(y)) * sqrt((viewVector.x * viewVector.x) + (viewVector.y * viewVector.y));
		}
		else
		{
			viewVector.z = -tan(DegreesToRadians(-y)) * sqrt((viewVector.x * viewVector.x) + (viewVector.y * viewVector.y));
		}
		return viewVector;
	}

	Vector Vector::VecToView() const
	{
		//Yaw angles
		Vector aimAngles{};
		if (x >= 0.0f && y < 0.0f) // +x, -y
		{
			aimAngles.x = RadiansToDegrees(atanf(x / -y));
		}
		else if (x >= 0.0f && y >= 0.0f) // +x, +y
		{
			aimAngles.x = RadiansToDegrees(atanf(y / x)) + 90.0f;
		}
		else if (x < 0.0f && y >= 0.0f) // -x, +y
		{
			aimAngles.x = RadiansToDegrees(atanf(-x / y)) + 180.0f;
		}
		else // -x, -y
		{
			aimAngles.x = RadiansToDegrees(atanf(-y / -x)) + 270.0f;
		}

		//Pitch angles
		if (z >= 0.0f)
		{
			aimAngles.y = RadiansToDegrees(atanf(z / sqrtf(x * x + y * y)));
		}
		else
		{
			aimAngles.y = -RadiansToDegrees(atanf(-z / sqrtf(x * x + y * y)));
		}
		return aimAngles;
	}

	float Vector::VectorDotProduct(const Vector& vector) const
	{
		return (x * vector.x) + (y * vector.y) + (z * vector.z);
	}

	float Vector::CalcVectorLength() const
	{
		return sqrt((x * x) + (y * y) + (z * z));
	}

	Vector Vector::operator-(const Vector& vector) const
	{
		Vector vectorBetweenPoints //vector to enemy (dest(enemy) - source(player))
		{
			x - vector.x, //distance between x postions
			y - vector.y, //distance between y positions
			z - vector.z //distance between z positions
		};

		return vectorBetweenPoints;
	}

	float RadiansToDegrees(float rad)
	{
		return ((rad * 180.0f) / 3.14159265359f);
	}

	float DegreesToRadians(float deg)
	{
		return ((deg / 180.0f) * 3.14159265359f);
	}
}