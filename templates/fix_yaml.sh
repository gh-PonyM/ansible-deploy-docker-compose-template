#!/usr/bin/env bash

set - eu
{% for file in ('templates/docker-compose.yml',) %}
sed -i s/\'{/\"{/g {{ output_role_path }}/{{ file }}
sed -i s/}\'/}\"/g {{ output_role_path }}/{{ file }}
{% endfor %}
