
    # Output to asked file
    action(type="omfile"
           name="{{output_name}}"
           DynaFile="{{template_id}}"
           flushInterval="{{flush_interval}}"
           asyncWriting="{{async_writing}}"
           Template="{% if stock_as_raw %}raw_to_json{% else %}{{ out_template }}{% endif %}"
           CreateDirs="on"
           dirCreateMode="0700"
           FileCreateMode="0644")
