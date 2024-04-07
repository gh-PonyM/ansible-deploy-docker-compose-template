from __future__ import annotations

from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel


class Default(BaseModel):
    key: str
    original_key: Optional[str] = None
    value: Union[int, str, dict]
    is_secret: bool
    service: str
    secret_path: Optional[str] = None
    secret_expr: Optional[str] = None
    env_file: Optional[str] = None


class Networks(BaseModel):
    default: None


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
