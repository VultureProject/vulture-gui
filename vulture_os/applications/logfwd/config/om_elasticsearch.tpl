
    action(type="omelasticsearch"
           name="{{output_name}}"
           server={{ servers }}
           searchIndex="{{ template_id }}"
           template="{{ out_template }}_elastic"
           dynSearchIndex="on"
           searchType="_doc" # compatibility with Elasticsearch >= 7
           {%- if uid and pwd %}
           uid="{{ uid }}"
           pwd="{{ pwd }}"
           {%- endif %}
           {%- if ssl_ca %}tls.cacert="{{ssl_ca}}"{%- endif %}
           {%- if ssl_cert %}tls.mycert="{{ssl_cert}}"{%- endif %}
           {%- if ssl_key %}tls.myprivkey="{{ssl_key}}"{%- endif %}
        {%- if ratelimit_interval %}
           retryfailures="on"
        {%- endif %}
        {%- if ratelimit_interval %}
           RateLimit.Interval="{{ratelimit_interval}}"
        {%- endif %}
        {%- if ratelimit_burst %}
           RateLimit.Burst="{{ratelimit_burst}}"
        {%- endif %}
           bulkmode="on"
           maxbytes="100m"
           queue.type="linkedlist"
           queue.size="5000"
           queue.dequeuebatchsize="300"
           action.resumeretrycount="-1")
