# Role {{ cli_output['role_name'] }}

This role was generated be role {{ role_name }}

## docker-compose.yml template

```yaml
---
{{ cli_output['final_compose'] | to_nice_yaml(sort_keys=False, indent=2) }}
```
## Defaults

| Variable | default  | ENV | used by | is secret |
| -------- |----------|-----| ------- |-----------|
{% for def in cli_output.defaults  %}
| `{{ def.key }}` | {{ def.value }} | `{{ def.original_key | default('') }}` | {{ def.service }} | {{ def.is_secret }} |
{% endfor %}
