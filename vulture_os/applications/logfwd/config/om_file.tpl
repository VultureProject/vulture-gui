
    # Output to asked file
    action(type="omfile"
           name="{{output_name}}"
           DynaFile="{{template_id}}"
           flushInterval="{{flush_interval}}"
           asyncWriting="{{async_writing}}"
           Template="{{ out_template }}"
           CreateDirs="on"
           dirCreateMode="0700"
           FileCreateMode="0644")
