action(type="omsentinel"
            name="{{output_name}}"
            tenant_id="{{tenant_id}}"
            client_secret="{{client_secret}}"
            client_id="{{client_id}}"
            scope="{{scope}}"
            grant_type="client_credentials"
            dcr="{{dcr}}"
            dce="{{dce}}"
            stream_name="{{stream_name}}"
            batch.maxsize="{{batch_maxsize}}"
            batch.maxbytes="{{batch_maxbytes}}"
            template="{% if send_as_raw %}raw_message{% else %}{{ out_template }}_json{% endif %}"
            errorfile="/var/log/internal/{{output_name}}_error.log"
        {%- if use_proxy %}
            {%- if proxy_host %}
            proxyhost="{{proxy_host}}"
            {%- endif %}
            {%- if proxy_port %}
            proxyport="{{proxy_port}}"
            {%- endif %}
        {%- endif %}
        {%- if compression_level %}
            compress="on"
            compress.level="{{compression_level}}"
        {%- endif %}
        {%- if ssl_cert %}
            tls.mycert="{{ssl_cert}}"
        {%- endif %}
        {%- if ssl_ca %}
            tls.cacert="{{ssl_ca}}"
        {%- endif %}
        {%- if ssl_key %}
            tls.myprivkey="{{ssl_key}}"
        {%- endif %}
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
            action.ResumeRetryCount = "-1"
        {%- if enable_disk_assist %}
            queue.highWatermark="{{high_watermark}}"
            queue.lowWatermark="{{low_watermark}}"
            queue.spoolDirectory="{{spool_directory}}"
            queue.filename="{{output_name}}_disk-queue"
            queue.maxFileSize="{{max_file_size}}m"
            queue.maxDiskSpace="{{max_disk_space}}m"
            queue.checkpointInterval="1024"
            queue.saveOnShutdown="on"
        {%- endif %} {# if enable_disk_assist #}
        {%- endif %} {# if enable_retry #}
        )