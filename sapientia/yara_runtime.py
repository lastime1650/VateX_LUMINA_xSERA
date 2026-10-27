"""Direct isolated interpreter command, including Windows venv package paths."""

import os
import site
import sys


def isolated_command(script):
    executable = sys.executable
    if os.name == "nt" and getattr(sys, "_base_executable", None):
        # A Windows venv executable is a launcher. Killing it on timeout does
        # not reliably stop its actual child. Spawn the base interpreter itself.
        executable = sys._base_executable
    paths = site.getsitepackages()
    # These paths come from the configured local runtime, never from rule text,
    # sample bytes, environment PYTHONPATH or a submitted compiled object.
    bootstrap = "import sys\nsys.path[:0] = " + repr(paths) + "\n" + script
    return [executable, "-I", "-B", "-X", "utf8", "-c", bootstrap]
