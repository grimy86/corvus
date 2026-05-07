# Security Policy
## Supported Versions
Security vulnerabilities may be reported in any version, including development builds.

However, only actively maintained versions receive fixes and patches.
Older or experimental versions may be acknowledged but not patched.

## Scope
Muninn is a low-level Windows systems library providing:
- process and memory inspection
- injection and hooking primitives
- PE parsing and module analysis
- thread and token manipulation utilities

The following are considered **in scope security issues**:
- memory corruption in library code
- privilege misuse due to implementation bugs
- incorrect validation leading to invalid process access
- unsafe handling of kernel/user boundaries
- exploitable buffer overflows or use-after-free in Muninn internals

The following are **out of scope**:
- misuse of APIs by consumers
- intentional use for injection/hooking in third-party processes
- operating system or third-party application vulnerabilities
- design choices that require elevated privileges

## Reporting a Vulnerability
If you believe you have found a security issue in Muninn, please report it privately:

**Email:** grimy86@proton.me

Please include:
- description of the issue
- minimal reproduction steps
- affected version
- potential impact

## Response Policy
You can expect:
- acknowledgement within 14 days
- initial assessment within 31 days
- fix timeline depending on severity:
  - critical: prioritized immediate patch
  - high: addressed in next release cycle
  - low: may be deferred

## Disclosure Policy
- Security issues will be patched before public disclosure.
- Coordinated disclosure is preferred.
- Credit will be given unless anonymity is requested.
