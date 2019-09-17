
    action(type="omelasticsearch"
           name="{{output_name}}"
           server={{ servers }}
           searchIndex="{{ template_id }}"
           template="{{ out_template }}"
           dynSearchIndex="on"
           {% if uid and pwd %}
           uid="{{ uid }}"
           pwd="{{ pwd }}"
           {% endif %}
           {% if ssl_ca %}tls.cacert="{{ssl_ca}}"
           {% if ssl_cert %}tls.mycert="{{ssl_cert}}"
           {% if ssl_key %}tls.myprivkey="{{ssl_key}}"
           bulkmode="on"
           maxbytes="100m"
           queue.type="linkedlist"
           queue.size="5000"
           queue.dequeuebatchsize="300"
           action.resumeretrycount="-1")
