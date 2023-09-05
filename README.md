# deploy-docker-compose-template

Makes converting a docker-compose.yml setup into an ansible role faster. The templates works in conjunction with the 
script `dc_to_ansible.py` that extracts information from multiple compose files. The cli does:

- Use `docker compose config` in order to interpolate the setup
- Identify secret strings and construct a **secret path** using one of the supported **secret provider**
- Transforming env vars into ansible defaults
- Identifies all exposed ports of the setup (e.g. might be used for firewall rules config by ansible)
- Identifies mounted volumes locally or docker volumes and extracts paths for eventual backup configs
- Generates a final combined docker-compose config injecting external `proxy-tier` network if needed.

Ansible on the other can takes the cli artefact as json and uses it to interpolate the role.

- Renders the role files using a different set of jinja2 start- and end-blocks.
- Creates the role and an **example playbook** with all the vars coming from the defaults but using the secret provider for secrets.

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