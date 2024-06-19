{%- if retry_on_els_failures %}
ruleset(name="{{output_name}}_retry_failure") {
    action(type="omfile" template="RSYSLOG_DebugFormat" file="/var/log/internal/{{output_name}}_error.log")
}

ruleset(name="{{output_name}}_retry") {
    if strlen($.omes!status) > 0 then {
        # retry case
        if ($.omes!status == 200) or ($.omes!status == 201) or (($.omes!status == 409) and ($.omes!writeoperation == "create")) then {
            stop # successful
        }
        if ($.omes!writeoperation == "unknown") or (strlen($.omes!error!type) == 0) or (strlen($.omes!error!reason) == 0) then {
            call {{output_name}}_retry_failure
            stop
        }
        if ($.omes!status == 400) or ($.omes!status < 200) then {
            call {{output_name}}_retry_failure
            stop
        }
        # else fall through to retry operation
    }
    if strlen($.omes!_id) > 0 then {
        set $.generated_uuid = $.omes!_id;
    } else {
        set $.generated_uuid = $uuid;
    }

    action(type="omelasticsearch"
            name="{{output_name}}_retry"
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
            queue.spoolDirectory="{{spool_directory}}"
            queue.filename="{{output_name}}_retry_disk-queue"
            queue.maxFileSize="{{max_file_size}}m"
            queue.maxDiskSpace="{{max_disk_space}}m"
            queue.checkpointInterval="128"
            queue.saveOnShutdown="on"
        {%- endif -%} {# if enable_disk_assist #}
    {%- endif -%} {# if enable_retry #}
            searchType=""
            bulkid="bulkid-template"
            dynbulkid="on"
            writeoperation="create"
            retryfailures="on"
            retryruleset="{{output_name}}_retry"
            )
}
{%- endif -%} {# if retry_on_els_failures #}
