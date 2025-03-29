import shutil
from pathlib import Path

import pytest


@pytest.mark.parametrize("compose", ("wg-easy.yml", "nginx-proxy-acme.yml", "minio.yml", "wikijs.yml", "pihole.yml"))
def test_create_role(compose, fixture_path, output_dir, copie):
    name = compose.replace(".yml", "")
    compose_p = fixture_path / compose
    dst_path = output_dir / name
    if dst_path.is_dir():
        shutil.rmtree(dst_path)
    dst_path.mkdir()
    copie.test_dir = dst_path
    ctx = {
        "project_name": name,
        "compose_file_path": str(compose_p.resolve()),
        "remove_cli_artefact": False
    }
    result = copie.copy(template_dir=Path("."), extra_answers=ctx)
    assert not result.exception
    assert False
