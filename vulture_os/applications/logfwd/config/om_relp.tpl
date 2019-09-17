    action(type="omrelp"
           name="{{output_name}}"
           Target="{{target}}"
           Port="{{port}}"
           Template="{{out_template}}"
           TLS="{% if tls %}on{% else %}off{% endif -%}"
           {% if ssl_ca -%}TLS.CaCert="{{ssl_ca}}" {%- endif -%}
           {% if ssl_cert -%}TLS.MyCert="{{ssl_cert}}" {%- endif -%}
           {% if ssl_key -%}TLS.MyPrivKey="{{ssl_key}}" {%- endif -%}
    )
