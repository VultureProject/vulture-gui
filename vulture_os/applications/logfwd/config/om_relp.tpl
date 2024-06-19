    action(type="omrelp"
            name="{{output_name}}"
            Target="{{target}}"
            Port="{{port}}"
            Template="{% if send_as_raw %}raw_message{% else %}{{ out_template }}{% endif %}"
            TLS="{% if tls %}on{% else %}off{% endif -%}"
            {% if ssl_ca -%}TLS.CaCert="{{ssl_ca}}" {%- endif -%}
            {% if ssl_cert -%}TLS.MyCert="{{ssl_cert}}" {%- endif -%}
            {% if ssl_key -%}TLS.MyPrivKey="{{ssl_key}}" {%- endif -%}
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
            queue.checkpointInterval="128"
            queue.saveOnShutdown="on"
            {%- endif -%} {# if enable_disk_assist #}
            {%- endif -%} {# if enable_retry #}
            )
