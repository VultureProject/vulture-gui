    # Output to asked file
    action(type="omfile"
            name="{{output_name}}"
            DynaFile="{{template_id}}"
            flushInterval="{{flush_interval}}"
            asyncWriting="{{async_writing}}"
            Template="{% if send_as_raw %}raw_message{% else %}{{ out_template }}{% endif %}"
            CreateDirs="on"
            dirCreateMode="0700"
            FileCreateMode="0644"
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
            queue.spoolDirectory="/var/tmp"
            queue.filename="{{output_name}}_disk-queue"
            queue.maxFileSize="{{max_file_size}}m"
            queue.maxDiskSpace="{{max_disk_space}}m"
            queue.checkpointInterval="128"
            queue.saveOnShutdown="on"
            {%- endif -%} {# if enable_disk_assist #}
            {%- endif -%} {# if enable_retry #}
            )
