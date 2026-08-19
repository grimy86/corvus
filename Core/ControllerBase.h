#pragma once
#include "IController.h"

/// <summary>
/// A base class for implementing controller logic.
/// </summary>
class ControllerBase : public IController
{
private:
    ControllerState m_state;

protected:
	// Derived classes must implement this method to release resources and return true if successful, false otherwise.
    bool Dispose() noexcept override;

	// Derived classes can call this method to set the controller state.
    void SetState(const ControllerState state) noexcept final override;

public:
    ControllerBase() noexcept;
    ~ControllerBase() noexcept override;

	// Returns the current state of the controller.
    const ControllerState& GetState() const noexcept final override;
};