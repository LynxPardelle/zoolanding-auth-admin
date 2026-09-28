# Linux Lambda dependencies — 2026-09-07 (Central Time)

Local TASK-029 packaging now resolves runtime wheels for Linux x86_64 / Python
3.13 rather than the build host. A regression assertion first failed for all
three dependency-bearing targets; the corrected builder passes it. The actual
built cryptography and CFFI wheels declare manylinux x86_64 compatibility.

The actual-archive audit also caught a Windows CFFI console launcher created by
pip despite the target-platform option. The builder omits that unused CLI;
two further regression tests enforce its removal and reject foreign binaries.

No authentication behavior, permission, source allowlist, activation flag,
workflow dispatch, or AWS resource was changed.
