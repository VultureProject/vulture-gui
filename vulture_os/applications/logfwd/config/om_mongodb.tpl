    action(type="ommongodb"
           name="{{output_name}}"
           template="{{out_template}}_mongo"
           uristr="{{uristr}}"
           {% if ssl_cert %}ssl_cert="{{ssl_cert}}"{% endif %}
           {% if ssl_ca %}ssl_ca="{{ssl_ca}}"{% endif %}
           db="{{db}}"
           collection="{{collection}}")
