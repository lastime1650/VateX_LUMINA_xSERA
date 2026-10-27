"""Embed the complete source identity in wheels without a source digest cycle.

This inventory is not an independent publisher signature. Signed installation,
protected installed files and independently signed qualification receipts are
the trust boundary; the inventory lets a receipt bind the actual runtime bytes.
"""

import sys
from pathlib import Path

from setuptools import setup
from setuptools.command.bdist_wheel import bdist_wheel


class SourceIdentityWheel(bdist_wheel):
    def write_wheelfile(self, wheelfile_base, generator="bdist_wheel"):
        super().write_wheelfile(wheelfile_base, generator)
        root = Path(__file__).resolve().parent
        sys.path.insert(0, str(root))
        from sapientia import release_manifest

        if Path(release_manifest.__file__).resolve() != root / "sapientia/release_manifest.py":
            raise ValueError("Wheel source inventory imported another application tree")
        manifest = release_manifest.build(root)
        (Path(wheelfile_base) / release_manifest.INSTALLED_MANIFEST).write_bytes(
            release_manifest.canonical(manifest)
        )


setup(cmdclass={"bdist_wheel": SourceIdentityWheel})
