#pragma once
#include "ControllerState.h"

/// <summary>
/// <para> A move-only interface for classes that manage exclusive-ownership resources and state. </para>
/// <para> Each instance owns its resource uniquely. However, it can be transferred (moved) between
/// owners, but never duplicated (copied). </para>
/// <para> The same underlying resource should never be owned by two objects at once. </para>
/// </summary>
class IController
{
protected:
    /// <summary>
	/// <para> Releases or cleans up controller-owned resources (e.g. closes a handle). </para>
	/// <para> Pure virtual: every derived controller must define its own cleanup logic. </para>
    /// </summary>
    /// <returns> True if the release succeeded. </returns>
    virtual bool Dispose() noexcept = 0;

    /// <summary>
    /// <para> Updates the controller's internal state (e.g. Uninitialized, Initialized, etc.). </para>
    /// <para> Protected because state transitions are an internal concern, not something
    /// external callers should be able to force directly. </para>
    /// </summary>
    /// <param name="state"></param>
    virtual void SetState(ControllerState state) noexcept = 0;

    /// <summary>
    /// <para> Reports the controller's current state. </para>
    /// const because reading state
    /// shouldn't require (or allow) mutating the object. </para>
    /// </summary>
    /// <returns></returns>
    virtual const ControllerState& GetState() const noexcept = 0;

public:
    /// <summary>
	/// <para> Default construction is allowed. </para>
    /// <para> Derived classes may choose to leave the controller in an uninitialized state with no
	/// resource attached yet </para>
    /// </summary>
    IController() noexcept = default;

    /// <summary>
	/// <para> Copying is explicitly disallowed. </para>
	/// <para> If this were allowed, two IController objects could both believe they own the same underlying resource (e.g. the same OS handle) </para>
    /// </summary>
    /// <param name=""></param>
    IController(const IController&) = delete;
    IController& operator=(const IController&) = delete;

    /// <summary>
	/// <para> Moving is allowed. </para>
	/// <para> Unlike copying, a move transfers ownership rather than duplicating it</para>
	/// <para> This lets controllers be returned from factory functions (like ProcessController::FromName), stored in containers (e.g. std::vector), etc. </para>
    /// </summary>
    /// <param name=""></param>
    IController(IController&&) noexcept = default;
    IController& operator=(IController&&) noexcept = default;

    /// <summary>
	/// <para> Virtual destructor ensures that derived class destructors are called when deleting through a base pointer. </para>
    /// </summary>
    virtual ~IController() noexcept = default;
};