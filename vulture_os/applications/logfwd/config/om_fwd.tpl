    action(type="omfwd"
           name="{{output_name}}"
           Target="{{target}}"
           Port="{{port}}"
           Protocol="{{protocol}}"
           Template="{% if send_as_raw %}raw_message{% else %}{{ out_template }}{% endif %}"
        {%- if ratelimit_interval %}
           RateLimit.Interval="{{ratelimit_interval}}"
        {%- endif %}
        {%- if ratelimit_burst %}
           RateLimit.Burst="{{ratelimit_burst}}"
        {%- endif %}
           ZipLevel="{{zip_level}}"
          )
