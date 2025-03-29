import shutil

import pytest

from extensions.dc_to_ansible import run


def find_in(items, key: str, value):
    for item in items:
        if item[key] == value:
            return item


@pytest.mark.skipif(
    not shutil.which("docker"), reason="Docker is not installed. but the cli calls it"
)
@pytest.mark.parametrize("file_name", ("wikijs.yml",))
def test_wikijs(fixture_path, file_name):
    file = fixture_path / file_name
    def_prefix = "xx_"
    role_name = file_name.split(".")[0]
    run(file=file, defaults_prefix=def_prefix, role_name=role_name)


@pytest.mark.skipif(
    not shutil.which("docker"), reason="Docker is not installed. but the cli calls it"
)
def test_doco_pihole(fixture_path):
    file = fixture_path / "pihole.yml"
    def_prefix = "phh_"
    role_name = "pihole"
    data = run(file=file, defaults_prefix=def_prefix, role_name=role_name).model_dump()

    # test defaults
    defaults = data["defaults"]

    # check secret detection
    pw = find_in(defaults, "key", f"{def_prefix}webpassword")
    assert pw["is_secret"] is True
    assert data["secret_provider"] == "passwordstore"
    env_key = pw["original_key"]
    secret_expr = pw["secret_expr"]
    assert (
        f"services/{role_name}/pihole/{env_key} create=true length={len(pw['value'])}'"
        in secret_expr
    )

    env_dnssec = find_in(defaults, "key", f"{def_prefix}dnssec")

    # check parsing boolean value
    assert env_dnssec["value"] == "true"

    # test releases
    assert data["images_tags"]["pihole/pihole:latest"] == {
        "service": "pihole",
        "tag": "latest",
    }

    # test final compose
    compose = data["final_compose"]
    svc_name = "pihole"
    svc = compose["services"][svc_name]
    assert svc["image"] == f"pihole/pihole:{{{{ {def_prefix}releases['{svc_name}'] }}}}"

    # test networks
    assert data["proxy_container"] is None
    assert not svc.get("networks"), (
        "original compose does not list networks and no proxy_container was given to the cli"
    )

    # test volumes
    assert data["volume_defaults"]["./etc-pihole"] == f"{def_prefix}pihole_mount_dir"
    assert svc["volumes"][0] == f"{{{{ {def_prefix}pihole_mount_dir }}}}:/etc/pihole"
    assert (
        svc["volumes"][1] == f"{{{{ {def_prefix}dnsmasq_d_mount_dir }}}}:/etc/dnsmasq.d"
    )

    # test ports
    assert svc["ports"][0] == f"{{{{ {def_prefix}host_port_pihole_53 }}}}:53/tcp"
    print(list(d["key"] for d in defaults))
    assert find_in(defaults, "key", f"{def_prefix}host_port_pihole_53")


def test_env_from_file_from_env_key(fixture_path):
    file = fixture_path / "minio.yml"
    def_prefix = "minio_"
    role_name = "minio"
    uid = 999
    data = run(
        file=file,
        defaults_prefix=def_prefix,
        role_name=role_name,
        uid=uid,
        proxy_container="minio",
    ).model_dump()
    # test defaults
    defaults_ = data["defaults"]
    vol = find_in(defaults_, "original_key", "MINIO_VOLUMES")
    assert vol["env_file"] == "./config/minio.env"
    assert data["final_compose"]["services"]["minio"]["user"] == f"{uid}:{uid}"


def test_env_from_file(fixture_path):
    file = fixture_path / "wg-easy.yml"
    def_prefix = "wg_"
    role_name = "wireguard"
    uid = 999
    data = run(
        file=file,
        defaults_prefix=def_prefix,
        role_name=role_name,
        uid=uid,
        proxy_container="wg",
    ).model_dump()
    # test defaults
    defaults_ = data["defaults"]
    vol = find_in(defaults_, "original_key", "PASSWORD_HASH")
    assert vol["env_file"] == "./wg_easy_env", "ansible must template this file"

    wg_service = data["final_compose"]["services"]["wg"]
    assert wg_service["env_file"], "cli should not remove the env_file key"
    assert not wg_service["environment"].get("PASSWORD_HASH"), (
        "defaults should have been removed and not taken from docker compose config"
    )
