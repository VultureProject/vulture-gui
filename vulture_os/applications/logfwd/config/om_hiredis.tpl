    action(type="omhiredis"
            name="{{output_name}}"
            server="{{target}}"
            serverport="{{port}}"
            mode="{{mode}}"
        {%- if dynamic_key %}
            key="{{template_id}}"
            DynaKey="on"
        {%- else %}
            key="{{key}}"
        {%- endif %}
        {%- if pwd %}
            ServerPassword="{{pwd}}"
        {%- endif %}
        {%- if mode == "queue" %}
            Userpush="{{ "on" if use_rpush else "off" }}"
        {%- endif %}
        {%- if mode == "set" %}
            Expiration="{{expire_key}}"
        {%- endif %}
        {%- if mode == "stream" %}
            stream.outField="{{stream_outfield}}"
        {%- endif %}
        {%- if mode == "stream" %}
            stream.capacityLimit="{{stream_capacitylimit}}"
        {%- endif %}
            Template="{% if send_as_raw %}raw_message{% else %}{{ out_template }}_json{% endif %}"
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
