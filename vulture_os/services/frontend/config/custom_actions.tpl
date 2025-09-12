{% for condition_block in custom_actions -%}
# Block {{ loop.index }}
{% for condition in condition_block -%}
    {%- if not loop.first %}} else {% endif -%}
    {%- if condition.condition == "" -%}
    {%- if loop.length > 1 -%}{ {{ condition.comment }}{%- endif -%}
    {%- else -%}
    if {{ condition.condition }} then { {{ condition.comment }}
    {%- endif -%}{# if condition.condition == "" #}
    {{ condition.action }}
{% if loop.last and (loop.length > 1 or condition.condition != "") %}}{% endif %}
{%- endfor %}{# for condition in condition_block #}
{% endfor %}{# for condition_block in custom_actions #}
