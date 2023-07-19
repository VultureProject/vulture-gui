
    action(type="omelasticsearch"
            name="{{output_name}}"
            server={{ servers }}
        {%- if es8_compatibility %}
            esVersion.major="8"
        {%- endif %}
            searchIndex="{{ template_id }}"
            template="{{ out_template }}_elastic"
            dynSearchIndex="on"
        {%- if uid and pwd %}
            uid="{{ uid }}"
            pwd="{{ pwd }}"
        {%- endif %}
        {%- if ssl_ca %}
            tls.cacert="{{ssl_ca}}"
        {%- endif %}
        {%- if ssl_cert %}
            tls.mycert="{{ssl_cert}}"
        {%- endif %}
        {%- if ssl_key %}
            tls.myprivkey="{{ssl_key}}"
        {%- endif %}
            bulkmode="on"
            maxbytes="100m"
            queue.type="LinkedList"
            queue.size="{{queue_size}}"
            queue.dequeuebatchsize="{{dequeue_size}}"
    {%- if enable_retry %}
            action.ResumeRetryCount = "-1"
        {%- if enable_disk_assist %}
            queue.highWatermark="{{high_watermark}}"
            queue.lowWatermark="{{low_watermark}}"
            queue.spoolDirectory="/var/tmp"
            queue.filename="{{output_name}}_disk-queue"
            queue.maxFileSize="{{max_file_size}}m"
            queue.maxDiskSpace="{{max_disk_space}}m"
            queue.checkpointInterval="128"
            queue.saveOnShutdown="on"
        {%- endif -%} {# if enable_disk_assist #}
    {%- endif -%} {# if enable_retry #}
            )
