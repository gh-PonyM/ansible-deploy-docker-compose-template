import json
import re
import shutil

import pytest

from scripts.dc_to_ansible import main


def find_in(items, key: str, value):
    for item in items:
        if item[key] == value:
            return item


@pytest.mark.skipif(
    not shutil.which("docker"), reason="Docker is not installed. but the cli calls it"
)
def test_doco_pihole(runner, fixture_path):
    file = fixture_path / "pihole.yml"
    def_prefix = "phh_"
    role_name = "pihole"
    r = runner.invoke(
        main,
        [
            "--file",
            str(file.resolve()),
            "--defaults-prefix",
            def_prefix,
            "--role-name",
            role_name,
        ],
    )
    assert r.exit_code == 0
    json_raw = r.stdout
    data = json.loads(json_raw)
    # print(json_raw)

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
    assert not svc.get(
        "networks"
    ), "original compose does not list networks and no proxy_container was given to the cli"

    # test volumes
    assert data["volume_defaults"]["./etc-pihole"] == f"{def_prefix}pihole_mount_dir"
    assert svc["volumes"][0] == f"{{{{ {def_prefix}pihole_mount_dir }}}}:/etc/pihole"
    assert svc["volumes"][1] == f"{{{{ {def_prefix}dnsmasq_d_mount_dir }}}}:/etc/dnsmasq.d"

    # test ports
    assert svc["ports"][0] == f"{{{{ {def_prefix}host_port_pihole_53 }}}}:53/tcp"
    print(list(d["key"] for d in defaults))
    assert find_in(defaults, "key", f"{def_prefix}host_port_pihole_53")
