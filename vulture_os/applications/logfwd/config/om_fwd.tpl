    action(type="omfwd"
           name="{{output_name}}"
           Target="{{target}}"
           Port="{{port}}"
           Protocol="{{protocol}}"
           Template="{% if send_as_raw %}raw_message{% else %}{{ out_template }}{% endif %}"
           ZipLevel="{{zip_level}}"
          )
