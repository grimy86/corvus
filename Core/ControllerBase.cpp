#include "ControllerBase.h"

ControllerBase::ControllerBase() noexcept
    : m_state(ControllerState::Uninitialized)
{
}

ControllerBase::~ControllerBase() noexcept
{
    if (m_state != ControllerState::Initialized)
        return;

    const bool isDisposed = Dispose();
    m_state = isDisposed
        ? ControllerState::Disposed
        : ControllerState::DestructorError;
}

bool ControllerBase::Dispose() noexcept
{
    if (m_state != ControllerState::Initialized)
        return false;

    m_state = ControllerState::Disposed;
    return true;
}

void ControllerBase::SetState(const ControllerState state) noexcept
{
    m_state = state;
}

const ControllerState& ControllerBase::GetState() const noexcept
{
    return m_state;
}