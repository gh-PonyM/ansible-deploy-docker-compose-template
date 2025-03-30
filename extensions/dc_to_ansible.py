from __future__ import annotations

import contextlib
import json
import logging
import os
import re
import subprocess
from collections import defaultdict
from functools import lru_cache
from json import JSONDecodeError
from pathlib import Path
import typing as t
import yaml
from copier_templates_extensions import ContextHook


from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr


from typing import Any, Dict, List, Optional, Union


class Default(BaseModel):
    key: str
    original_key: Optional[str] = None
    value: Union[int, str, dict]
    is_secret: bool
    service: str
    secret_path: Optional[str] = None
    secret_expr: Optional[str] = None
    env_file: Optional[str] = None


class Port(BaseModel):
    mode: str
    target: int
    published: str
    protocol: str


class TagDefinition(BaseModel):
    service: str
    tag: str


class OutputModel(BaseModel):
    role_name: str
    defaults: List[Default]
    ansible_vars: Dict[str, Any]
    example_defaults: Dict[str, Any]
    compose_vars_file: Dict[str, Any]
    secret_provider: str
    defaults_prefix: str
    secret_string_template: str
    compose_files: List[str]
    compose_config: dict
    final_compose: dict
    services_by_env: Dict[str, List[str]]
    proxy_container: None | str
    backup_paths: List[str]
    example_playbook: List
    exposed_ports_by_service: Dict[str, List[int]]
    volume_defaults: Dict[str, str]
    images_tags: Dict[str, TagDefinition]
    external_proxy_net: str
    env_files: Dict[str, str]

    def dump(self):
        return self.model_dump_json(indent=2, exclude_defaults=False)


class Cgroup(Enum):
    host = "host"
    private = "private"


class CredentialSpec(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    config: str | None = None
    file: str | None = None
    registry: str | None = None


class Condition(Enum):
    service_started = "service_started"
    service_healthy = "service_healthy"
    service_completed_successfully = "service_completed_successfully"


class DependsOn(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    restart: bool | None = None
    required: bool | None = True
    condition: Condition


class Extends(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    service: str
    file: str | None = None


class Logging(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    driver: str | None = None
    options: Dict[constr(pattern=r"^.+$"), str | float | None] | None = None


class Ports(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    name: str | None = None
    mode: str | None = None
    host_ip: str | None = None
    target: int | None = None
    published: str | int | None = None
    protocol: str | None = None
    app_protocol: str | None = None


class PullPolicy(Enum):
    always = "always"
    never = "never"
    if_not_present = "if_not_present"
    build = "build"
    missing = "missing"


class Selinux(Enum):
    z = "z"
    Z = "Z"


class Bind(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    propagation: str | None = None
    create_host_path: bool | None = None
    selinux: Selinux | None = None


class Volume1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    nocopy: bool | None = None
    subpath: str | None = None


class Tmpfs(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    size: conint(ge=0) | str | None = None
    mode: float | None = None


class Volumes(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    type: str
    source: str | None = None
    target: str | None = None
    read_only: bool | None = None
    consistency: str | None = None
    bind: Bind | None = None
    volume: Volume1 | None = None
    tmpfs: Tmpfs | None = None


class Healthcheck(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    disable: bool | None = None
    interval: str | None = None
    retries: float | None = None
    test: str | List[str] | None = None
    timeout: str | None = None
    start_period: str | None = None
    start_interval: str | None = None


class Action(Enum):
    rebuild = "rebuild"
    sync = "sync"
    sync_restart = "sync+restart"


class WatchItem(BaseModel):
    ignore: List[str] | None = None
    path: str | None = None
    action: Action | None = None
    target: str | None = None


class Development(BaseModel):
    watch: List[WatchItem] | None = None


class Order(Enum):
    start_first = "start-first"
    stop_first = "stop-first"


class RollbackConfig(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    parallelism: int | None = None
    delay: str | None = None
    failure_action: str | None = None
    monitor: str | None = None
    max_failure_ratio: float | None = None
    order: Order | None = None


class UpdateConfig(RollbackConfig):
    pass


class Limits(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    cpus: float | str | None = None
    memory: str | None = None
    pids: int | None = None


class RestartPolicy(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    condition: str | None = None
    delay: str | None = None
    max_attempts: int | None = None
    window: str | None = None


class Preference(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    spread: str | None = None


class Placement(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    constraints: List[str] | None = None
    preferences: List[Preference] | None = None
    max_replicas_per_node: int | None = None


class DiscreteResourceSpec(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: str | None = None
    value: float | None = None


class GenericResource(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    discrete_resource_spec: DiscreteResourceSpec | None = None


class GenericResources(RootModel[List[GenericResource]]):
    root: List[GenericResource]


class ConfigItem(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    subnet: str | None = None
    ip_range: str | None = None
    gateway: str | None = None
    aux_addresses: Dict[constr(pattern=r"^.+$"), str] | None = None


class Ipam(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    driver: str | None = None
    config: List[ConfigItem] | None = None
    options: Dict[constr(pattern=r"^.+$"), str] | None = None


class External(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    name: str | None = None


class External2(BaseModel):
    name: str | None = None


class Command(RootModel[str | List[str] | None]):
    root: str | List[str] | None


class EnvFile1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    path: str
    required: bool | None = True


class EnvFile(RootModel[str | List[str | EnvFile1]]):
    root: str | List[str | EnvFile1]


class ListOfStrings(RootModel[List[str]]):
    root: List[str]


class ListOrDict(
    RootModel[Dict[constr(pattern=r".+"), str | float | bool | None] | List[str]]
):
    root: Dict[constr(pattern=r".+"), str | float | bool | None] | List[str]


class BlkioLimit(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    path: str | None = None
    rate: int | str | None = None


class BlkioWeight(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    path: str | None = None
    weight: int | None = None


class ServiceConfigOrSecret1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    source: str | None = None
    target: str | None = None
    uid: str | None = None
    gid: str | None = None
    mode: float | None = None


class ServiceConfigOrSecret(RootModel[List[str | ServiceConfigOrSecret1]]):
    root: List[str | ServiceConfigOrSecret1]


class Ulimits1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    hard: int
    soft: int


class Ulimits(RootModel[Dict[constr(pattern=r"^[a-z]+$"), int | Ulimits1]]):
    root: Dict[constr(pattern=r"^[a-z]+$"), int | Ulimits1]


class Constraints(RootModel[Any]):
    root: Any


class Build(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    context: str | None = None
    dockerfile: str | None = None
    dockerfile_inline: str | None = None
    entitlements: List[str] | None = None
    args: ListOrDict | None = None
    ssh: ListOrDict | None = None
    labels: ListOrDict | None = None
    cache_from: List[str] | None = None
    cache_to: List[str] | None = None
    no_cache: bool | None = None
    additional_contexts: ListOrDict | None = None
    network: str | None = None
    pull: bool | None = None
    target: str | None = None
    shm_size: int | str | None = None
    extra_hosts: ListOrDict | None = None
    isolation: str | None = None
    privileged: bool | None = None
    secrets: ServiceConfigOrSecret | None = None
    tags: List[str] | None = None
    ulimits: Ulimits | None = None
    platforms: List[str] | None = None


class BlkioConfig(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    device_read_bps: List[BlkioLimit] | None = None
    device_read_iops: List[BlkioLimit] | None = None
    device_write_bps: List[BlkioLimit] | None = None
    device_write_iops: List[BlkioLimit] | None = None
    weight: int | None = None
    weight_device: List[BlkioWeight] | None = None


class Networks(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    aliases: ListOfStrings | None = None
    ipv4_address: str | None = None
    ipv6_address: str | None = None
    link_local_ips: ListOfStrings | None = None
    mac_address: str | None = None
    priority: float | None = None


class Device(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    capabilities: ListOfStrings | None = None
    count: str | int | None = None
    device_ids: ListOfStrings | None = None
    driver: str | None = None
    options: ListOrDict | None = None


class Devices(RootModel[List[Device]]):
    root: List[Device]


class Network(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    name: str | None = None
    driver: str | None = None
    driver_opts: Dict[constr(pattern=r"^.+$"), str | float] | None = None
    ipam: Ipam | None = None
    external: External | None = None
    internal: bool | None = None
    enable_ipv6: bool | None = None
    attachable: bool | None = None
    labels: ListOrDict | None = None


class Volume(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    name: str | None = None
    driver: str | None = None
    driver_opts: Dict[constr(pattern=r"^.+$"), str | float] | None = None
    external: External | None = None
    labels: ListOrDict | None = None


class Secret(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    name: str | None = None
    environment: str | None = None
    file: str | None = None
    external: External2 | None = None
    labels: ListOrDict | None = None
    driver: str | None = None
    driver_opts: Dict[constr(pattern=r"^.+$"), str | float] | None = None
    template_driver: str | None = None


class Config(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    name: str | None = None
    content: str | None = None
    environment: str | None = None
    file: str | None = None
    external: External2 | None = None
    labels: ListOrDict | None = None
    template_driver: str | None = None


class StringOrList(RootModel[str | ListOfStrings]):
    root: str | ListOfStrings


class Reservations(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    cpus: float | str | None = None
    memory: str | None = None
    generic_resources: GenericResources | None = None
    devices: Devices | None = None


class Resources(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    limits: Limits | None = None
    reservations: Reservations | None = None


class Deployment(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    mode: str | None = None
    endpoint_mode: str | None = None
    replicas: int | None = None
    labels: ListOrDict | None = None
    rollback_config: RollbackConfig | None = None
    update_config: UpdateConfig | None = None
    resources: Resources | None = None
    restart_policy: RestartPolicy | None = None
    placement: Placement | None = None


class Include1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    path: StringOrList | None = None
    env_file: StringOrList | None = None
    project_directory: str | None = None


class Include(RootModel[str | Include1]):
    root: str | Include1


class Service(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    develop: Development | None = None
    deploy: Deployment | None = None
    annotations: ListOrDict | None = None
    attach: bool | None = None
    build: str | Build | None = None
    blkio_config: BlkioConfig | None = None
    cap_add: List[str] | None = None
    cap_drop: List[str] | None = None
    cgroup: Cgroup | None = None
    cgroup_parent: str | None = None
    command: Command | None = None
    configs: ServiceConfigOrSecret | None = None
    container_name: str | None = None
    cpu_count: conint(ge=0) | None = None
    cpu_percent: conint(ge=0, le=100) | None = None
    cpu_shares: float | str | None = None
    cpu_quota: float | str | None = None
    cpu_period: float | str | None = None
    cpu_rt_period: float | str | None = None
    cpu_rt_runtime: float | str | None = None
    cpus: float | str | None = None
    cpuset: str | None = None
    credential_spec: CredentialSpec | None = None
    depends_on: (
        ListOfStrings | Dict[constr(pattern=r"^[a-zA-Z0-9._-]+$"), DependsOn] | None
    ) = None
    device_cgroup_rules: ListOfStrings | None = None
    devices: List[str] | None = None
    dns: StringOrList | None = None
    dns_opt: List[str] | None = None
    dns_search: StringOrList | None = None
    domainname: str | None = None
    entrypoint: Command | None = None
    env_file: EnvFile | None = None
    environment: ListOrDict | None = None
    expose: List[str | float] | None = None
    extends: str | Extends | None = None
    external_links: List[str] | None = None
    extra_hosts: ListOrDict | None = None
    group_add: List[str | float] | None = None
    healthcheck: Healthcheck | None = None
    hostname: str | None = None
    image: str | None = None
    init: bool | None = None
    ipc: str | None = None
    isolation: str | None = None
    labels: ListOrDict | None = None
    links: List[str] | None = None
    logging: Logging | None = None
    mac_address: str | None = None
    mem_limit: float | str | None = None
    mem_reservation: str | int | None = None
    mem_swappiness: int | None = None
    memswap_limit: float | str | None = None
    network_mode: str | None = None
    networks: (
        ListOfStrings
        | Dict[constr(pattern=r"^[a-zA-Z0-9._-]+$"), Networks | None]
        | None
    ) = None
    oom_kill_disable: bool | None = None
    oom_score_adj: conint(ge=-1000, le=1000) | None = None
    pid: str | None = None
    pids_limit: float | str | None = None
    platform: str | None = None
    ports: List[float | str | Ports] | None = None
    privileged: bool | None = None
    profiles: ListOfStrings | None = None
    pull_policy: PullPolicy | None = None
    read_only: bool | None = None
    restart: str | None = None
    runtime: str | None = None
    scale: int | None = None
    security_opt: List[str] | None = None
    shm_size: float | str | None = None
    secrets: ServiceConfigOrSecret | None = None
    sysctls: ListOrDict | None = None
    stdin_open: bool | None = None
    stop_grace_period: str | None = None
    stop_signal: str | None = None
    storage_opt: Dict[str, Any] | None = None
    tmpfs: StringOrList | None = None
    tty: bool | None = None
    ulimits: Ulimits | None = None
    user: str | None = None
    uts: str | None = None
    userns_mode: str | None = None
    volumes: List[str | Volumes] | None = None
    volumes_from: List[str] | None = None
    working_dir: str | None = None


class ComposeSpecification(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    version: str | None = Field(
        None, description="declared for backward compatibility, ignored."
    )
    name: constr(pattern=r"^[a-z0-9][a-z0-9_-]*$") | None = Field(
        None,
        description="define the Compose project name, until user defines one explicitly.",
    )
    include: List[Include] | None = Field(
        None, description="compose sub-projects to be included."
    )
    services: Dict[constr(pattern=r"^[a-zA-Z0-9._-]+$"), Service] | None = None
    networks: Dict[constr(pattern=r"^[a-zA-Z0-9._-]+$"), Network | None] | None = None
    volumes: Dict[constr(pattern=r"^[a-zA-Z0-9._-]+$"), Volume | None] | None = None
    secrets: Dict[constr(pattern=r"^[a-zA-Z0-9._-]+$"), Secret] | None = None
    configs: Dict[constr(pattern=r"^[a-zA-Z0-9._-]+$"), Config] | None = None


secret_provider_default = "passwordstore"
file_docker_file_mount_identifier: str = "# deploy-docker-compose-template::type"
file_type_env = f"{file_docker_file_mount_identifier}::env"

default_min_secret_len = 12


@contextlib.contextmanager
def cd_to_directory(path: Path):
    """Changes working directory and returns to previous on exit."""
    prev_cwd = Path.cwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(prev_cwd)


def is_secret(
    service_name, key, value, secret_seqs: t.Sequence[str] | None = None
) -> bool:
    """Determines the type of variables by key name. Add additional logic using the service name of needed"""
    patt = re.compile(
        "(password|secret|token|api_key|db_pass|secret_key)$", flags=re.IGNORECASE
    )
    if patt.search(key):
        return True
    elif secret_seqs and re.search(rf"({'|'.join(secret_seqs)})", key):
        return True
    return False


def patch_port(port_line: str, new_key):
    return re.sub(r"^\d+", new_key, port_line)


@lru_cache
def run(
    file: Path,
    defaults_prefix: str,
    role_name: str,
    uid: int | None = None,
    secret_provider=secret_provider_default,
    secret_string_template: str = "services/{role_name}/{service_name}/{env_key}",
    proxy_container: str | None = None,
    min_secret_length: int = default_min_secret_len,
    ext_proxy_net="proxy-tier",
    out: Path | None = None,
) -> OutputModel | None:
    """Converts a docker-compose file into an ansible role"""

    if not defaults_prefix.endswith("_"):
        defaults_prefix = f"{defaults_prefix}_"

    def normalize_key_and_name(name: str):
        return re.sub(r"[\s-]]", "_", name).lower()

    def variable_from_env(key):
        return f"{defaults_prefix}{normalize_key_and_name(key)}"

    def variable_from_port(
        service_name: str, exposed_port: int, add_prefix: bool = True
    ):
        return f"{defaults_prefix if add_prefix else ''}host_port_{service_name}_{exposed_port}"

    with cd_to_directory(file.parent):
        yaml_config = subprocess.check_output(
            (
                "docker",
                "compose",
                "-f",
                file.name,
                "config",
                "--format",
                "json",
                "--no-path-resolution",
            ),
            encoding="utf-8",
        )
    try:
        yaml_data: dict = json.loads(yaml_config)
    except JSONDecodeError:
        # see bug https://github.com/docker/compose/issues/11669
        yaml_data = yaml.safe_load(yaml_config)

    model = ComposeSpecification.model_validate(yaml_data)
    final = yaml.safe_load(file.read_text(encoding="utf-8"))
    ComposeSpecification.model_validate(final)

    bootstrap_data: dict = {
        "role_name": normalize_key_and_name(role_name),
        "defaults": [],
        "ansible_vars": {},
        "example_defaults": {},
        "compose_vars_file": {},
        "secret_provider": secret_provider,
        "defaults_prefix": defaults_prefix,
        "secret_string_template": secret_string_template,
        "compose_files": [str(file.resolve())],
        "compose_config": yaml_data,
        "final_compose": {},
        "services_by_env": {},
        "proxy_container": proxy_container,
        "backup_paths": [],
        "example_playbook": [],
        "exposed_ports_by_service": defaultdict(list),
        "volume_defaults": {},
        "images_tags": [],
        "external_proxy_net": ext_proxy_net,
        "env_files": {},
    }

    services_by_env = defaultdict(list)
    volume_defaults = {}
    images_tags: dict[str:dict] = {}
    releases_key = normalize_key_and_name("releases")

    def get_secret_path(svc_name, key):
        context = dict(
            role_name=bootstrap_data["role_name"], service_name=svc_name, env_key=key
        )
        return secret_string_template.format(**context)

    def file_name_id(path: str):
        return normalize_key_and_name("_".join(Path(path).parts[-1].split(".")))

    def env_to_dict(env_: list | t.Iterable[str]) -> dict:
        e = {}
        for item in env_:
            k, v = item.split("=", 1)
            e[k] = v
        return e

    def env_from_file(p: Path, compose_env_file: bool = False) -> dict[str, str | int]:
        """Parses the env file and returns a dictionary of key value pairs
        For regular files: requires a line on top of the file
        For service.env_file files: set compose_env_file to True
        """

        def iterate():
            for ix, line in enumerate(p.read_text(encoding="utf-8").splitlines()):
                if (
                    not compose_env_file
                    and ix == 0
                    and not line.startswith(file_type_env)
                ):
                    # The user actually has to provide the file outside the logic of the role
                    break
                if not line or line.startswith("#"):
                    continue
                yield line

        return env_to_dict(iterate())

    def patch_image_tag(image: str, new_tag: str):
        splits = image.split(":")
        return ":".join((*splits[:-1], new_tag))

    def get_secret_expr(
        item: dict,
    ):
        """Returns the jinja variable expression using the secret path as defined by the secret_path template."""
        secret_len = max((len(item["value"]), min_secret_length))
        return f"{{{{ lookup('community.general.passwordstore', '{item['secret_path']} create=true length={secret_len}') }}}}"

    def add_to_defaults(
        key,
        val,
        service_name: str,
        is_secret: bool = False,
        env_file: str | None = None,
    ):
        if services_by_env.get(key):
            return
        normalized_key = variable_from_env(key)
        data = {
            "key": normalized_key,
            "original_key": key,
            "value": val,
            "is_secret": is_secret,
            "service": service_name,
        }
        if is_secret:
            data["secret_path"] = get_secret_path(service_name, key)
            data["secret_expr"] = get_secret_expr(data)
        if env_file:
            data["env_file"] = env_file
            bootstrap_data["env_files"][env_file] = file_name_id(env_file)
        bootstrap_data["defaults"].append(data)
        services_by_env[key].append(service_name)

    def handle_secret_env_var(svc_name: str, key, value, env_file: str | None = None):
        add_to_defaults(key, value, svc_name, is_secret=True, env_file=env_file)

    def handle_env_var(svc_name: str, key, value, env_file: str | None = None):
        add_to_defaults(key, value, svc_name, is_secret=False, env_file=env_file)

    def handle_svc_environment(name: str, svc: Service):
        env = svc.environment
        if not env:
            return
        env_file: str | list[str] = final["services"][name].get("env_file")
        names_to_env_files = {}
        if env_file:
            env_f_list = [env_file] if isinstance(env_file, str) else env_file
            for ix, fp in enumerate(resolve_env_files(env_f_list)):
                file_env_data = env_from_file(fp, compose_env_file=True)
                names_to_env_files.update({k: env_f_list[ix] for k in file_env_data})
        # includes all env vars, also from env_file
        for key, value in env.root.items():
            if is_secret(name, key, value):
                handle_secret_env_var(
                    name, key, value, env_file=names_to_env_files.get(key)
                )
            else:
                handle_env_var(name, key, value, env_file=names_to_env_files.get(key))

    def handle_svc_env_file(name: str, path: str):
        """Takes every value scans for local files mounted as source into the container and extracts env vars from it.
        This is for the case where an env specifies the inner path to a config whereas ansible defaults contain these env vars
        in order to template this file to be mounted inside the docker container"""
        if path.startswith("/"):
            p = Path(path)
        else:
            p = file.parent / path
        p = p.resolve()
        if not p.is_file():
            return
        try:
            env = env_from_file(p)
        except Exception:
            logging.warning(f"Supposed env file {p} could not be parsed")
            return
        for key, value in env.items():
            if is_secret(name, key, value):
                handle_secret_env_var(name, key, value, path)
            else:
                handle_env_var(name, key, value, path)

    def handle_networks(networks_data: dict | None):
        if not networks_data:
            return

    def handle_svc_ports(name: str, data: Service):
        if not data.ports:
            return
        for port in data.ports:
            if not port.published:
                continue
            host_port = int(port.published)
            bootstrap_data["exposed_ports_by_service"][name].append(host_port)
            key = variable_from_port(name, host_port, add_prefix=False)
            add_to_defaults(key, host_port, name)

    def handle_svc_volumes(
        name: str, data: Service, volumes: dict[str, Volume | None] | None
    ):
        for vol in data.volumes or []:
            if vol.type == "bind":
                val = vol.source
                bootstrap_data["backup_paths"].append(val)
                handle_svc_env_file(name, path=val)
                m = re.search(r"[\w._]+$", val)
                vol_id = m.group(0) if m else "data"
                vol_id = vol_id.replace(".", "_")
                normalized_key = f"{defaults_prefix}{vol_id}_mount_dir"
                volume_defaults[val] = normalized_key

            elif vol.type == "volume":
                # may add the default path for docker volumes
                default_path = "/var/lib/docker/volumes"
                vol_path = volumes[vol.source].name
                bootstrap_data["backup_paths"].append(f"{default_path}/{vol_path}")

    supported = ("mariadb", "postgres", "redis")
    db_search_patt = re.compile(rf"({'|'.join(supported)})")

    def handle_service_image(name, svc: Service):
        image = svc.image
        m = db_search_patt.search(image)
        tag = image.split(":")[-1]
        data = {"service": name, "tag": tag}
        if m:
            data["kind"] = m.group(1)
        images_tags[image] = data

    def add_releases_to_defaults():
        defaults = {}
        for image, image_data in images_tags.items():
            defaults[image_data["service"]] = image_data["tag"]
        bootstrap_data["defaults"].append(
            {
                "key": variable_from_env(releases_key),
                "value": defaults,
                "is_secret": False,
                "service": "None",
            }
        )

    def handle_services(model: ComposeSpecification):
        for svc_name, svc in model.services.items():
            handle_svc_environment(svc_name, svc)
            handle_svc_volumes(svc_name, svc, model.volumes)
            handle_svc_ports(svc_name, svc)
            handle_service_image(svc_name, svc)

    def handle_proxy_container(compose_config: dict):
        if not proxy_container:
            return compose_config
        compose_config.setdefault("networks", {})
        compose_config["services"][proxy_container].setdefault("networks", [])
        compose_config["services"][proxy_container]["networks"].append(ext_proxy_net)
        if len(compose_config["services"][proxy_container]["networks"]) == 1:
            compose_config["services"][proxy_container]["networks"].append("default")
        compose_config["networks"].setdefault(
            ext_proxy_net, {"name": ext_proxy_net, "external": True}
        )
        return compose_config

    def resolve_env_files(file_list):
        for f in file_list:
            if f.startswith("/"):
                p = Path(f)
            else:
                p = file.parent / f
            yield p

    def create_final_compose(final_compose: dict):
        """Creates the final modified docker-compose.yml file with secret string
        and external networks added. Uses the original compose file before running
        `docker compose config` since this straps away the version of the files etc."""
        for name, data in final_compose["services"].items():
            env_ = data.get("environment", {})
            if isinstance(env_, list):
                env_ = env_to_dict(env_)
                final_compose["services"][name]["environment"] = env_
            for key, val in env_.items():
                lookup_var = variable_from_env(key)
                final_compose["services"][name]["environment"][key] = (
                    f"{{{{ {lookup_var} }}}}"
                )
            for ix, vol in enumerate(data.get("volumes", [])):
                val = model.services[name].volumes[ix].source
                # val = vol["source"]
                if val in volume_defaults:
                    data["volumes"][ix] = data["volumes"][ix].replace(
                        val, f"{{{{ {volume_defaults[val]} }}}}"
                    )
            new_ports = []
            for port_entry, exposed_port in zip(
                data.get("ports", []),
                bootstrap_data["exposed_ports_by_service"].get(name, []),
            ):
                new_ports.append(
                    patch_port(
                        port_entry,
                        f"{{{{ {variable_from_port(name, exposed_port)} }}}}",
                    )
                )
            if new_ports:
                data["ports"] = new_ports
            img = data["image"]
            new_tag = f"{{{{ {variable_from_env(releases_key)}['{name}'] }}}}"
            data["image"] = patch_image_tag(img, new_tag)
            if uid and data.get("user"):
                data["user"] = re.sub(r"\d+", str(uid), data["user"])

        final_compose = handle_proxy_container(final)
        bootstrap_data["final_compose"] = final
        return final_compose

    handle_networks(model.networks)
    handle_services(model)
    add_releases_to_defaults()
    create_final_compose(final)
    bootstrap_data["services_by_env"] = services_by_env
    bootstrap_data["volume_defaults"] = volume_defaults
    bootstrap_data["images_tags"] = images_tags
    model = OutputModel.model_validate(bootstrap_data)
    if out:
        out.write_text(model.dump(), encoding="utf-8")
    else:
        return model


def resolve_docker_compose_path(answer: str, target_dir: Path) -> Path:
    if answer.startswith("/"):
        file = Path(answer)
    else:
        file = target_dir / answer
    if not file.is_file():
        raise FileNotFoundError(f"File {file.resolve()} does not exist")
    return file


class ContextUpdater(ContextHook):
    def hook(self, context) -> None:
        answers = context["_copier_answers"]
        dest = context["_copier_conf"]["dst_path"]
        cli_data_model = run(
            file=resolve_docker_compose_path(answers["compose_file_path"], dest),
            defaults_prefix=answers["ansible_defaults_prefix"],
            role_name=answers["role_name"],
            uid=answers["docker_user_id"],
            secret_provider=answers["secret_provider"],
            secret_string_template=answers["secret_string_template"],
            min_secret_length=answers["min_secret_length"],
            ext_proxy_net=answers.get("ext_proxy_net", context["ext_proxy_net"]),
            proxy_container=answers.get("proxy_container_net_attach"),
        )
        context["cli_output"] = cli_data_model.model_dump(
            mode="json", exclude_defaults=False
        )
