    action(type="omfwd"
            name="{{output_name}}"
            Target="{{target}}"
            Port="{{port}}"
            Protocol="{{protocol}}"
            Template="{% if send_as_raw %}raw_message{% else %}{{ out_template }}{% endif %}"
            {%- if ratelimit_interval %}
            RateLimit.Interval="{{ratelimit_interval}}"
            {%- endif %}
            {%- if ratelimit_burst %}
            RateLimit.Burst="{{ratelimit_burst}}"
            {%- endif %}
            ZipLevel="{{zip_level}}"
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