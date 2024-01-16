import shutil
import subprocess

import pytest


@pytest.mark.skipif(not shutil.which("ansible"), reason="ansible not installed")
@pytest.mark.parametrize("compose", ("wikijs.yml", "pihole.yml"))
def test_create_role(temporary_directory, compose, fixture_path):
    cmd = (
        "ansible-playbook",
        "tests/test_pb.yml",
        "-e",
        f"out_roles_path={temporary_directory}",
        "-e",
        f"compose_file_path={fixture_path / compose}",
    )
    r = subprocess.run(cmd, encoding="utf-8", check=False, capture_output=True)
    print(r.stdout)
    assert r.returncode == 0
