# 001: Use Python

Status: Accepted

Use Python for the vulnerability patching harness, preferring the standard library and minimal dependencies. The
existing Java and Python services retain their languages.

Tools/libraries to use:
- ``uv`` to select the correct python version and manage the environment, dependencies, and lockfile.
- ``Pydantic v2`` for strict input models

Python supports a small, offline, testable implementation within the 4.5-hour timebox. This is the implementation choice
made by the author, not an assignment requirement.
