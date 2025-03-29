# deploy-docker-compose-template

Makes converting a docker-compose.yml setup into an ansible role faster using [`copier`](https://copier.readthedocs.io/en/stable/).

## Requirements

To bootstrap the template, `copier` tools is used alongside custom jinja extensions:

    pipx install copier
    pipx inject copier copier-templates-extensions

Usage:

    copier gh:gh-PonyM/deploy-docker-compose-template --trust <target_dir>

## Notes on generated ansible role

### Docker compose versions

- As of version 2.18.0, docker compose v2 module can be used. This requires `python-docker` package and `docker-compose-plugin` apt packages to be installed.
- For docker compose v1, use `compose_v1: true`. This installs docker-compose python package and the docker package as pip package for docker user. (You might need the package `acl` installed when you run into privilege escalation problems)

## Current limitations

- If any of the `docker-compose.yml` defaults have  `{{` in it, you have to override the ansible default with `!unsafe "{{ ..."` manually
- The service names inside `docker-compose.yml` shall not use spaces or `-`. Always use `_` to be compatible with ansible variables
- `env_file` support is limited. On `docker compose config`, the variables are merged with values in `environment`. Use the pre-startup commands to generate this env file

## Conversion Steps inside the template

The template rendering context is enriched using a [custom extension](extensions/dc_to_ansible.py) that:

- Uses `docker compose config` in order to analyze the compose file.
- Identifies secret strings and construct a **secret path** using one of the supported **secret provider**
  - Uses the length of the example secret in `docker-compose.yml` or uses `min_secret_length`, whatever is longer
- Transforms env vars into ansible **defaults**
- If a `user` key is present for a service, it signals a rootless deployment (either `user: 1000` oder with a group: `user: 1000:1000`). The uid is replaced with `docker_user_id` from the copier answers.
- Identifies all exposed ports of the setup (e.g. might be used for firewall rules config by ansible)
- Identifies mounted volumes locally or docker volumes and extracts paths for eventual backup configs
- Generates a final combined docker-compose config injecting external `proxy-tier` network if needed.

### Environment to defaults conversion

- All variables defined by `environment` are converted into role defaults
- If a file is mounted from `compose_file_path`, it's checked if it can be read as an env file, and rendered as part of the role. See [minio example](tests/fixtures/minio.yml)
- If an `env_file` is specified instead of `environment`, you have to create this file yourself via the pre-startup commands.
