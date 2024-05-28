# deploy-docker-compose-template

Makes converting a docker-compose.yml setup into an ansible role faster. The templates works in conjunction with the 
script `dc_to_ansible.py` that extracts information from one compose file. **This role is meant to be used on an ansible controller machine with `connection: local`**.

## Docker compose versions

- As of version 2.18.0, docker compose v2 module can be used. This requires `python-docker` package and `docker-compose-plugin` apt packages to be installed.
- For docker compose v1, use `compose_v1: true`. This installs docker-compose python package and the docker package as pip package for docker user. (You might need the package `acl` installed when you run into privilege escalation problems)

## Current limitations

- If any of the `docker-compose.yml` defaults have  `{{` in it, you have to override the ansible default with `!unsafe "{{ ..."`
- The service names inside `docker-compose.yml` shall not use spaces or `-`. Always use `_` to be compatible with ansible variables

**dc_to_ansible.py**

The cli can be used standalone and the generated json used for other things. Here is what it does:

- Uses `docker compose config` in order to analyze the compose file.
- Identifies secret strings and construct a **secret path** using one of the supported **secret provider**
  - Uses the length of the example secret in `docker-compose.yml` or uses `min_secret_length`, whatever is longer
- Transforms env vars into ansible **defaults**
- If a `user` key is present for a service, it signals a rootless deployment (either `user: 1000` oder with a group: `user: 1000:1000`). The uid is replaced with `docker_user_id` from the roles defaults
- Identifies all exposed ports of the setup (e.g. might be used for firewall rules config by ansible)
- Identifies mounted volumes locally or docker volumes and extracts paths for eventual backup configs
- Generates a final combined docker-compose config injecting external `proxy-tier` network if needed.

The cli uses `click` and `PyYAML` as dependency, both of them should be available when ansible is installed. 
Starting from version 1.2.0, the cli install its dependencies (`pydantic`) into the path `cli_virtualenv_path`, which by default `.venv` inside the role installation path.


    Usage: dc_to_ansible.py [OPTIONS]

      Converts a docker-compose file into an ansible role
    
    Options:
      -f, --file PATH                 Docker compose files
      -p, --defaults-prefix TEXT      The prefix used for all defaults
      --secret-provider [passwordstore]
                                      [default: passwordstore]
      --secret-string-template TEXT   Defines a string format for the path the
                                      secrets should be stored using defined
                                      secret provider.  [default: services/{role_n
                                      ame}/{service_name}/{env_key}]
      --proxy-container TEXT          Container name to add to the proxy network
      -n, --role-name TEXT            [default: docker_]
      --min-secret-length INTEGER     [default: 12]
      -e, --ext-proxy-net TEXT        Name of the external proxy net  [default:
                                      proxy-tier]
      -o, --out PATH                  Output file
      --uid INTEGER                   The users uid to use if user is defined on
                                      any service
      --help                          Show this message and exit.


The rest is done by ansible in order to interpolate a role and create an example playbook

**Example playbook**

```yaml
---

- hosts: localhost
  gather_facts: false
  connection: local
  vars:
    remove_cli_artefact: false
  tasks:
    - import_role:
        name: deploy-docker-compose-template
      vars:
        compose_file_path: "{{ playbook_dir }}/compose_files/someapp/docker-compose.yml"
        proxy_container_net_attach: wikijs
      tags: myapp
```

Add the role to **requirements.yml** using `ansible-galaxy install -r requirements.yml`

    ---
    roles:
    - src: git@gitlab.com:lksch-group/deploy-docker-compose-template.git
      scm: git
      version: 1.2.6
