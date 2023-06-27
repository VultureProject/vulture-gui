    action(type="omhiredis"
            name="{{output_name}}"
            server="{{target}}"
            serverport="{{port}}"
            mode="{{mode}}"
            key="{{key}}"
            ServerPassword="{{pwd}}"
            Template="{{ out_template }}_redis"
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
