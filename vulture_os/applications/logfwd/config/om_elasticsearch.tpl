    action(type="omelasticsearch"
            name="{{output_name}}"
            server={{ servers }}
        {%- if es8_compatibility %}
            esVersion.major="8"
        {%- endif %}
            searchIndex="{{ template_id }}"
            template="{% if send_as_raw %}raw_message{% else %}{{ out_template }}_elastic{% endif %}"
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
        {%- if queue_timeout_shutdown %}
            queue.timeoutshutdown="{{queue_timeout_shutdown}}"
        {%- endif %}
        {%- if max_workers %}
            queue.workerThreads="{{max_workers}}"
        {%- endif %}
        {%- if new_worker_minimum_messages %}
            queue.workerThreadMinimumMessages="{{new_worker_minimum_messages}}"
        {%- endif %}
        {%- if worker_timeout_shutdown %}
            queue.timeoutWorkerthreadShutdown="{{worker_timeout_shutdown}}"
        {%- endif %}
    {%- if enable_retry %}
            action.resumeRetryCount = "-1"
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
        {%- if data_stream_mode %}
            searchType=""
            bulkid="bulkid-template"
            dynbulkid="on"
            writeoperation="create"
        {%- endif -%} {# if data_stream_mode #}
            errorFile="/var/log/internal/{{output_name}}_error.log"
            )
