"""Linux systemd daemon and CLI executable entry point."""

import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from Agent.cli import main
from Agent.Linux.collector import LinuxCollector

if __name__ == "__main__":
    main("Linux", LinuxCollector)
