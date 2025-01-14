import shutil
import subprocess

import pytest


@pytest.mark.skipif(not shutil.which("ansible"), reason="ansible not installed")
@pytest.mark.parametrize("compose", ("nginx-proxy-acme.yml", "minio.yml", "wikijs.yml", "pihole.yml"))
def test_create_role(compose, fixture_path, output_dir):
    name = compose.rstrip(".yml")
    cmd = (
        "ansible-playbook",
        "tests/test_pb.yml",
        "-e",
        f"out_roles_path={output_dir}",
        "-e",
        f"compose_file_path={fixture_path / compose}",
        "-e",
        f"project_name={name}"
    )
    r = subprocess.run(cmd, encoding="utf-8", check=False, capture_output=True)
    print(r.stdout)
    assert r.returncode == 0
