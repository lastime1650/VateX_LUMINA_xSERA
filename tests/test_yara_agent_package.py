"""Both downloaded agent kits carry the new process-image collector at runtime."""

import io
import json
import subprocess
import sys
import zipfile

import pytest

from sapientia import agent_distribution
from tests.signing_support import release_signer  # noqa: F401

pytestmark = pytest.mark.usefixtures("release_signer")


@pytest.mark.parametrize("platform", ["windows", "linux"])
def test_downloaded_kit_imports_process_image_support_without_repository(
    platform, tmp_path
):
    blob, _, _ = agent_distribution.package(platform)
    with zipfile.ZipFile(io.BytesIO(blob)) as archive:
        manifest = json.loads(archive.read("manifest.json"))
        assert "Agent/process_artifact.py" in manifest["files"]
        assert manifest["process_artifact_collection"]["supported"]
        assert not manifest["process_artifact_collection"]["default_enabled"]
        assert not manifest["process_artifact_collection"]["sample_execution"]
        archive.extractall(tmp_path)
    script = (
        "import sys;sys.path.insert(0,"
        + repr(str(tmp_path))
        + ");import Agent.process_artifact as p;print(p.__file__);print(p.MAX_BYTES)"
    )
    completed = subprocess.run(
        [sys.executable, "-I", "-B", "-c", script],
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    )
    assert str(tmp_path / "Agent" / "process_artifact.py") in completed.stdout
    assert str(32 * 1024 * 1024) in completed.stdout
