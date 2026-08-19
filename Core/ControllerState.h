#pragma once

/// <summary>
/// Represents the state of a controller.
/// </summary>
enum class ControllerState
{
    Uninitialized,    // ControllerBase ctor ran, derived ctor not yet complete
    Initialized,      // Derived ctor succeeded, resources are allocated
    ConstructorError, // Derived ctor failed, object is not usable
    Disposed,         // Resources released cleanly
    DisposeError,     // Dispose() returned false during destruction
    DestructorError   // Some error occurred during destruction, object is not usable
};