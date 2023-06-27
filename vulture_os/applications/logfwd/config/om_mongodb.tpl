    action(type="ommongodb"
            name="{{output_name}}"
            template="{{out_template}}_mongo"
            uristr="{{uristr}}"
            {% if ssl_cert %}ssl_cert="{{ssl_cert}}"{% endif %}
            {% if ssl_ca %}ssl_ca="{{ssl_ca}}"{% endif %}
            db="{{db}}"
            collection="{{collection}}"
            queue.type="LinkedList"
            queue.size="{{queue_size}}"
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
