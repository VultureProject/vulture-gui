if (!String.prototype.endsWith) {
  String.prototype.endsWith = function(searchString, position) {
    var subjectString = this.toString();
    if (typeof position !== 'number' || !isFinite(position) || Math.floor(position) !== position || position > subjectString.length) {
      position = subjectString.length;
    }
    position -= searchString.length;
    var lastIndex = subjectString.lastIndexOf(searchString, position);
    return lastIndex !== -1 && lastIndex === position;
  };
}

function get_api_parser_data(type_){
  var data = {
    api_parser_type: $('#id_api_parser_type').val(),
    api_parser_use_proxy: $('#id_api_parser_use_proxy').is(':checked'),
    api_parser_custom_proxy: $('#id_api_parser_custom_proxy').val(),
    api_parser_verify_ssl: $('#id_api_parser_verify_ssl').is(':checked')
  };

  if ($('#id_api_parser_verify_ssl').is(':checked') && !api_parser_blacklist.includes($('#id_api_parser_type').val())) {
    data['api_parser_custom_certificate'] = $('#id_api_parser_custom_certificate').val();
  }

  $("#api_" + type_ + "_row input").each(function(){
    var name = $(this).attr('name');
    switch($(this).attr('type')){
      case "checkbox":
        data[name] = $(this).is(':checked');
        break;
      case "text":
        data[name] = $(this).val();
        break;
      case "password":
        data[name] = $(this).val();
        break;
    }
  })

  $('#api_'+ type_ + "_row textarea").each(function(){
    var name = $(this).attr('name');
    data[name] = $(this).val();
  })

  $('#api_' + type_ + "_row select").each(function(){
    var name = $(this).attr('name');
    data[name] = $(this).val();
  })

  return data;
}

function refresh_api_parser_type(type_){
  $('.api_clients_row').hide();

  if ($('#id_mode').val() === "log" && $('#id_listening_mode').val() === "api") {
    $('#id_node').hide();
    $('#api_' + type_ + "_row").show();

    if ($("#id_ruleset option[value='api_" + type_ + "-ecs']").length > 0) {
      $('#id_ruleset').val("api_" + type_ + "-ecs").trigger('change');
    } else if ($("#id_ruleset option[value='api_" + type_ + "']").length > 0) {
      $('#id_ruleset').val("api_" + type_).trigger('change');
    } else if ($("#id_ruleset option[value='" + type_ + "-ecs']").length > 0) {
      $('#id_ruleset').val(type_ + "-ecs").trigger('change');
    } else if ($("#id_ruleset option[value='" + type_ + "']").length > 0) {
      $('#id_ruleset').val(type_).trigger('change');
    } else {
      $('#id_ruleset').val('generic_json').trigger('change');
    }
  }

  $('.fetch_data_api_parser').unbind('click');
  $('.fetch_data_api_parser').on('click', function(){
    PNotify.removeAll();

    var btn = this;
    var txt = $(btn).html();
    $(btn).html('<i class="fa fa-spinner fa-spin"></i>');
    $(btn).prop('disabled', true);

    var target = $(this).data('target');
    var type_target = $(this).data('type');

    var data = get_api_parser_data(type_);

    $('#'+target).empty();

    $.post(
      fetch_frontend_api_parser_data_uri,
      data,

      function(response){
        $(btn).prop('disabled', false);
        $(btn).html(txt);
        if (!check_json_error(response))
          return;

        var data = response.data;
        if (type_target == "select"){
          for (var i in data)
            $('#'+target).append(new Option(data[i], data[i]))
        }
      }
    )
  })

  $('#test_api_parser').unbind('click');
  $('#test_api_parser').on('click', function(){
    PNotify.removeAll();
    if($('#id_api_parser_type').val() == "") {
      notify('error', gettext('Error'), gettext('Select an API Parser Type'))
      return
    }

    var btn = this;
    var txt = $(btn).html();
    $(btn).html('<i class="fa fa-spinner fa-spin"></i>');
    $(btn).prop('disabled', true);

    var data = get_api_parser_data(type_);

    $.post(
      test_frontend_apiparser_uri,
      data,

      function(response){
        $(btn).prop('disabled', false);
        $(btn).html(txt);
        if (!check_json_error(response)){
          $('#id_api_parser_has_been_tested').val('0');
          return;
        }

        var data = response.data;
        $('#id_api_parser_has_been_tested').val('1');
        $('#modal-test-apiparser-body').html('<pre>' + JSON.stringify(data, null, 4) + "</pre>");
        $('#modal-test-apiparser').modal('show');
      }
    ).fail(function(response){
      notify('error', response.status, response.responseText)

      $(btn).prop('disabled', false);
      $(btn).html(txt);
    })
  })
}

/* Redraw a switch to take new properties into account */
function redrawSwitch(id) {
  elem = document.getElementById(id);
  elem.removeAttribute('readonly');
  while(elem.nextElementSibling) elem.nextElementSibling.remove();
  Switchery(elem);
}

$(function() {

  /* All events to refresh (re-apply) after a table is modified */
  function refresh_table_events() {

    /* Function used to delete an object .btnDelete */
    $('.btnDelete').on('click', function(e) {
      $(this).parent().parent().remove();
    });

    /* Re-initialize select2 objects */
    $('.select2').select2();

    /* Re-initialize Tag-Editor events */
    /* Try to destroy old tag-editor elements */
    try { $(".tag-editor-space").tagEditor('destroy');
    } catch(e) {};
    try { $(".tag-editor-comma").tagEditor('destroy');
    } catch(e) {};
    /* And re-add TagEditor behavior for tag-editor custom classes */
    $(".tag-editor-space").tagEditor({
      delimiter: ' '
    });
    $(".tag-editor-comma").tagEditor({
      delimiter: ','
    });
  }

  function refresh_redis_local_use() {
    if ($('#id_redis_server').val() === redis_local.server
          && parseInt($('#id_redis_port').val()) === redis_local.port
          && $('#id_redis_password').val() === redis_local.password
        ) {
      $('#id_redis_use_local').prop('checked', true).trigger('change');
    }

    if ($("#id_redis_use_local").is(':checked')) {
      $('.redis-connect').hide();
    } else {
      $('.redis-connect').show();
    }
  }

  $('#stock_logs_locally').on('change', function(){
    var selected_forwarders = $('#id_log_forwarders').val();

    if (selected_forwarders === null)
      selected_forwarders = [];

    if( ($.inArray("1", selected_forwarders) === -1) && ($(this).is(':checked')) ) {
      selected_forwarders.push("1");
    } else if( ($.inArray("1", selected_forwarders) !== -1) && (!$(this).is(':checked')) ) {
      selected_forwarders.pop("1");
    }

    $('#id_log_forwarders').val(selected_forwarders).trigger('change');
  })

  $('#archive_logs').on('change', function(){
    var selected_forwarders = $('#id_log_forwarders').val();

    if (selected_forwarders === null)
      selected_forwarders = [];

    if( ($.inArray("2", selected_forwarders) === -1) && ($(this).is(':checked')) ) {
      selected_forwarders.push("2");
    } else if( ($.inArray("2", selected_forwarders) !== -1) && (!$(this).is(':checked')) ) {
      selected_forwarders.pop("2");
    }

    $('#id_log_forwarders').val(selected_forwarders).trigger('change');
  })

  /* Function used to auto-complete tagEditor */
  function autoComplete(list, begin) {
    var result = Array();
    var size_list = list.length;
    for( i=0 ; i<size_list ; i++ )
      if( list[i].startsWith(begin) )
        result.push(list[i]);
    return result;
  }

  /* Show network only fields, or hide them */
  function show_network_conf(mode, listening_mode, filebeat_listening_mode) {
    /* If it is an rsyslog / File only conf */
    if ((mode === "log" && listening_mode === "file") || (mode === "filebeat" && filebeat_listening_mode === "file" )) {
      $('.network-mode').hide();
      $('.api-mode').hide();
      $('.kafka-mode').hide();
      $('.redis-mode').hide();
      // ALWAYS put show at last
      $('.file-mode').show();
    } else if (mode === "filebeat" && filebeat_listening_mode === "api") {
      $('.network-mode').hide();
      $('.file-mode').hide();
      $('.kafka-mode').hide();
      $('.redis-mode').hide();
      $('.api-mode').hide();
      // ALWAYS put show at last
      $('.filebeat-api-mode').show();
    }else if (mode === "log" && listening_mode === "api") {
      $('.network-mode').hide();
      $('.file-mode').hide();
      $('.kafka-mode').hide();
      $('.redis-mode').hide();
      // ALWAYS put show at last
      $('.api-mode').show();
    } else if (mode === "log" && listening_mode === "kafka"){
      $('.network-mode').hide();
      $('.file-mode').hide();
      $('.api-mode').hide();
      $('.redis-mode').hide();
      // ALWAYS put show at last
      $('.kafka-mode').show();
    } else if (mode === "log" && listening_mode === "redis"){
      $('.network-mode').hide();
      $('.file-mode').hide();
      $('.api-mode').hide();
      $('.kafka-mode').hide();
      // ALWAYS put show at last
      $('.redis-mode').show();
    } else {
      $('.file-mode').hide();
      $('.api-mode').hide();
      $('.kafka-mode').hide();
      $('.redis-mode').hide();
      // ALWAYS put show at last
      $('.network-mode').show();
    }
  }

  /* Show rsyslog only fields, or hide them */
  function show_custom_conf(mode, listening_mode, filebeat_listening_mode) {
    /* If it is an UDP mode only => HAProxy is useless */
    if( (mode === "log" && ["udp", "file", "api", "kafka", "redis"].includes(listening_mode)) ||
        (mode === "filebeat" && ["udp", "file", "api"].includes(filebeat_listening_mode)) ) {
      $('.haproxy-conf').hide();
    } else {
      $('.haproxy-conf').show();
    }
  }

  /* Show fields, or hide them, depending on chosen listening mode */
  function show_tcp_conf(mode, listening_mode, filebeat_listening_mode) {
    /* If listening mode is TCP, show according options */
    if (mode === "log" && ["tcp", "tcp,udp", "relp"].includes(listening_mode)) {
      $('.listening-tcp').show();
    } else {
      $('.listening-tcp').hide();
    }
  }

  /* Show Redis settings, or hide them */
  function show_redis_conf(mode, listening_mode, filebeat_listening_mode) {
    if (mode === "log" && listening_mode === "redis") {
      $('#redis-settings').show()
      $('#id_redis_mode').trigger('change');
      refresh_redis_local_use();
    }
    else {
      $('#redis-settings').hide()
    }

    if (mode === "filebeat") {
      $('.filebeat-mode.redis-mode').show();
      refresh_redis_local_use();
    }
  }

  /* Show node field, or hide them, depending on chosen listening mode */
  function show_node(mode, listening_mode, filebeat_listening_mode) {
    /* If listening mode is TCP, show according options */
    if( (mode === "log" && ["file", "api", "kafka", "redis"].includes(listening_mode)) ||
    (mode === "filebeat" && ["file", "api"].includes(filebeat_listening_mode)) ) {
      $('#node-div').show();
    } else {
      $('#node-div').hide();
    }
  }

  function refresh_input_logs_type(mode, listening_mode, filebeat_listening_mode){
    var first = true;
    if((mode === "log") || (mode === "filebeat") ){
      $('#ruleset-div').show();
    }
    else {
      $('#ruleset-div').hide();
      if((mode === "log" && listening_mode === "api") || (mode === "filebeat" && filebeat_listening_mode === "api") ){
        // Bind API inputs
        $("#tab_api_client input").each(function(){
          $(this).unbind('click');
          $(this).on('click', function(e){
            $('#id_api_parser_has_been_tested').val('0');
          });
        });
      }
    }
  }

  function show_darwin_mode(darwin_policy) {
    if( darwin_policy ) {
      $('.darwin-mode').show();
    }
    else {
      $('.darwin-mode').hide();
    }
  }

  $('#id_api_parser_use_proxy').on('change', function(e){
    if ($(this).is(':checked')) {
      $('#api_parser_custom_proxy').show();
    } else $('#api_parser_custom_proxy').hide();
  }).trigger('change');

  $('#id_api_parser_verify_ssl').on('change', function(e){
    if ($(this).is(':checked') && !api_parser_blacklist.includes($('#id_api_parser_type').val())) {
      $('#api_parser_custom_certificate').show();
    } else $('#api_parser_custom_certificate').hide();
  }).trigger('change');

  $('#id_api_parser_type').on('change', function(){
    if($(this).val() == "") {
      $('#test_api_parser').prop("disabled", true);
    } else $('#test_api_parser').prop("disabled", false);
    refresh_api_parser_type($(this).val());
    $('#id_api_parser_verify_ssl').trigger('change');
  }).trigger('change');


  /* Refresh http sub-class attributes show/hide */
  function refresh_http() {
    if( $('#id_enable_cache').is(':checked') ) {
      $('.cache').show();
    } else {
      $('.cache').hide();
    }
    if( $('#id_enable_compression').is(':checked') ) {
      $('.compression').show();
    } else {
      $('.compression').hide();
    }
  }

  function refresh_dashboard_forwarder(old_mode, new_mode) {
    // retrieve selected forwarders
    var selected_forwarders = $('#id_log_forwarders').val();
    if (selected_forwarders === null)
      selected_forwarders = [];
    $('#id_log_forwarders').val(selected_forwarders).trigger('change');
  }

  /* Show fields depending on chosen mode */
  var last_enable_log = ($('#id_mode').val()!=="log" && $('#id_mode').val()!=="filebeat") ? ($('#id_enable_logging').is(":checked")) : (false);
  $('#id_mode').on('change', function(event) {
    var mode = $(this).val();
    $('.http-mode').hide();
    $('.tcp-mode').hide();
    $('.log-mode').hide();
    $('.filebeat-mode').hide();
    $('.'+mode+'-mode').show();

    /* If mode = LOG / Filebeat => Activate logging automatically */
    var log_enabled = $('#id_enable_logging').is(":checked");
    if( (mode === "log" || mode === "filebeat") && !log_enabled ) {
      $('#id_enable_logging').trigger('click');
      $('#id_enable_logging').prop("disabled", true);
      last_enable_log = log_enabled;
    } else if ( mode === "http" || mode === "tcp" ) {
      refresh_http();
      $('#id_enable_logging').prop("disabled", false);
      if( last_enable_log != log_enabled )
        $('#id_enable_logging').trigger('click');
    } else if ( mode === "log") {
      last_enable_log = log_enabled;
      $('#id_enable_logging').prop("disabled", true);
      if( $('#stock_logs_locally').is(':checked') ) {
        $('#stock_logs_locally').click();
      }

      refresh_input_logs_type(mode, $('#id_listening_mode').val(), $('#id_filebeat_listening_mode').val());
    }

    $('#id_enable_logging').trigger("change");
    refresh_ruleset($('#id_ruleset').val());

    show_custom_conf(mode, $('#id_listening_mode').val(), $('#id_filebeat_listening_mode').val());
    show_tcp_conf(mode, $('#id_listening_mode').val(), $('#id_filebeat_listening_mode').val());
    show_network_conf(mode, $('#id_listening_mode').val(), $('#id_filebeat_listening_mode').val());
    show_redis_conf(mode, $('#id_listening_mode').val(), $('#id_filebeat_listening_mode').val());
    show_node(mode, $('#id_listening_mode').val(), $('#id_filebeat_listening_mode').val());
    show_log_condition_failure();
    old_mode = mode;
  }).trigger('change');

  $('#id_queue_type').on('change', function(e){
    if ($(this).val() === "direct") {
      $('#tab-queue').hide();
    } else {
      $('#tab-queue').show();
    }
  }).trigger('change');

  $('#id_enable_disk_assist').on('change', function(e){
    if ($(this).is(':checked')) {
      $('#tab-disk').show();
    } else {
      $('#tab-disk').hide();
    }
  }).trigger('change');

  $('#id_redis_mode').on('change', function(event) {
    if ($(this).val() === "queue") {
      $('.redis-queue-mode').show();
      $('.redis-stream-mode').hide();
    }
    else if ($(this).val() === "stream") {
      $('.redis-queue-mode').hide();
      $('.redis-stream-mode').show();
    }
    else {
      $('.redis-queue-mode').hide();
      $('.redis-stream-mode').hide();
    }
    $('#id_redis_stream_consumerGroup').trigger('change')
  }).trigger('change');

  $('#id_redis_stream_consumerGroup').on('change', function(e){
    if ($(this).val() !== "" && $('#id_redis_mode').val() === "stream") {
      $('.redis-consumer-group').show();
    } else $('.redis-consumer-group').hide();
  }).trigger('change');

  var last_redis_server = $('#id_redis_server').val();
  var last_redis_port = $('#id_redis_port').val();
  var last_redis_password = $('#id_redis_password').val();

  $('#id_redis_use_local').on('change', function(event) {
    if ($(this).is(':checked')) {
      last_redis_server = $('#id_redis_server').val();
      last_redis_port = $('#id_redis_port').val();
      last_redis_password = $('#id_redis_password').val();
      $('#id_redis_server').val(redis_local.server);
      $('#id_redis_port').val(redis_local.port);
      $('#id_redis_password').val(redis_local.password);
      $('.redis-connect').hide();
    } else {
      $('#id_redis_server').val(last_redis_server);
      $('#id_redis_port').val(last_redis_port);
      $('#id_redis_password').val(last_redis_password);
      $('.redis-connect').show();
    }
  }).trigger('change');

  /* Show logging options if logging enabled */
  $('#id_enable_logging').on("change", function(e) {
    $('.log-mode-logging').hide();
    $('.http-mode-logging').hide();
    if( $('#id_enable_logging').is(":checked") ) {
      $('.logging').show();
      $('.'+$('#id_mode').val()+'-mode-logging').show();
    } else {
      $('.logging').hide();
      if( $('#id_enable_logging_reputation').is(":checked") ) {
        $('#id_enable_logging_reputation').trigger("click");
      }
    }
    redrawSwitch('id_enable_logging');
  }).trigger("change");

  $('#id_darwin_policies').on("change", function(e) {
    var policy = $(this).val();
    show_darwin_mode(policy);
  }).trigger('change');

  function refresh_filebeat_module() {
    var module = $("#id_filebeat_module").val();
    $('#id_filebeat_config').text(filebeat_config[module]);
  }

  function refresh_filebeat_ruleset(module) {
    if ($("#id_ruleset option[value='beat_" + module + "-ecs']").length > 0) {
      $('#id_ruleset').val("beat_" + module + "-ecs").trigger('change');
    } else if ($("#id_ruleset option[value='beat_" + module + "']").length > 0) {
      $('#id_ruleset').val("beat_" + module).trigger('change');
    } else {
      $('#id_ruleset').val('generic_json').trigger('change');
    }
  }

  $('#id_filebeat_module').on("change", function(e) {
    refresh_filebeat_module();
    // Automatically select parser if present
    refresh_filebeat_ruleset($(this).val());
  });
  refresh_filebeat_module();

  /* Show log_condition_failure depending on mode and ruleset */
  function show_log_condition_failure() {
    if( $('#id_mode').val() == "log" && ['raw_to_json'].indexOf($('#id_ruleset').val()) < 0 ) {
      $('.log-failure').show();
    } else {
      $('.log-failure').hide();
    }
  }

  /* Parser type bind */
  function refresh_ruleset(val) {
    if (!val) return;

    if( val === "forwarder" ) {
      $('.forwarder-tag').show();
    } else {
      $('.forwarder-tag').hide();
    }

    if( val.endsWith("_json") ) {
      $('.log-parser-json').show();
    } else {
      $('.log-parser-json').hide();
    }

    show_log_condition_failure();
  }
  $('#id_ruleset').on("change", function() {
    refresh_ruleset($(this).val());
  }).trigger('change');

  /* Listening_mode bind */
  $('#id_listening_mode').on("change", function(e) {
    show_custom_conf($('#id_mode').val(), $(this).val(), $('#id_filebeat_listening_mode').val());
    show_tcp_conf($('#id_mode').val(), $(this).val(), $('#id_filebeat_listening_mode').val());
    show_network_conf($('#id_mode').val(), $(this).val(), $('#id_filebeat_listening_mode').val());
    show_redis_conf($('#id_mode').val(), $(this).val(), $('#id_filebeat_listening_mode').val());
    show_node($('#id_mode').val(), $(this).val(), $('#id_filebeat_listening_mode').val());
    refresh_input_logs_type($('#id_mode').val(), $(this).val(), $('#id_filebeat_listening_mode').val());
  }).trigger('change');

  /* Filebeat listening_mode bind */
  $('#id_filebeat_listening_mode').on("change", function(e) {
    show_custom_conf($('#id_mode').val(), $('#id_listening_mode').val(), $(this).val());
    show_tcp_conf($('#id_mode').val(), $('#id_listening_mode').val(), $(this).val());
    show_network_conf($('#id_mode').val(), $('#id_listening_mode').val(), $(this).val());
    show_redis_conf($('#id_mode').val(), $('#id_listening_mode').val(), $(this).val());
    show_node($('#id_mode').val(), $('#id_listening_mode').val(), $(this).val());
    refresh_input_logs_type($('#id_mode').val(), $('#id_listening_mode').val(), $(this).val());
  }).trigger('change');

  /* Listeners code */
  var id = 0;
  /* Add default ListenerForm to listener_table */
  $("#add_listener").on("click", function(e) {
    $('#listener_table').append(listener_form_td);

    refresh_table_events();
    id++;
  });


  /* Cache enable bind */
  $('#id_enable_cache').on("change", function(e) {
    refresh_http();
  }).trigger("change");


  /* Compression enable bind */
  $('#id_enable_compression').on("change", function(e) {
    refresh_http();
  }).trigger("change");


  /* Reputation logging enable bind */
  $('#id_enable_logging_reputation').on("change", function(e) {
    if( $(this)[0].checked )
      $('.reputation-mode').show();
    else
      $('.reputation-mode').hide();
  }).trigger("change");


  /* Request-headers code */
  var id2 = 0;
  /* Add default HeaderForm to headers_table */
  $("#add_header").on("click", function(e) {
    $('#header_table').append(header_form_td);
    refresh_table_events();
    id2++;
  });

  /* Add an entry for keep_source_fields table */
  $("#add_keep_source_field").on("click", function(e) {
    $('#keep_source_fields_table').append('<tr><td><input type="text"/></td><td><input type="text"/></td><td style="text-align:center"><input type="checkbox"/></td><td style="text-align:center"><a class="btnDelete"><i style="color:grey" class="fas fa-trash-alt"></i></a></td></tr>');
    /* Function used to delete an object .btnDelete */
    $('.btnDelete').on('click', function(e) {
      $(this).parent().parent().remove();
    });
  });

  /* Build request-headers and listeners fields with tables content */
  $('#frontend_edit_form').submit(function(event) {
    if ($('#id_mode').val() === "log" && $('#id_listening_mode').val() === "api"){
      // Need to check if the API Parser has been tested
      if ($('#id_api_parser_has_been_tested').val() === "0"){
        event.preventDefault();
        notify('error', gettext('Error'), gettext('Test your API configuration before saving this frontend'))
        return;
      }
    }

    $('#id_ruleset').prop('disabled', false);
    var listeners = new Array();
    $('#listener_table tbody tr').each(function(index, tr) {
      var id = tr.children[0].innerHTML;
      var network_address_id = tr.children[1].children[0].value;
      var port = tr.children[2].children[0].valueAsNumber;
      var tls_profiles = $(tr.children[3].children[0]).val();
      // It's a bootstrap-tagsinput, so retrieve the second child
      // Temporary fix suggested by KGU to prevent bugs with the tagsinput lib imported
      var wl_ips = undefined;
      if (tr.children[4].children[1] !== undefined) {
          wl_ips = tr.children[4].children[1].value;
      } else {
          wl_ips = tr.children[4].children[0].value;
      }

      var max_src = tr.children[5].children[0].valueAsNumber;
      var max_rate = tr.children[6].children[0].valueAsNumber;
      listeners.push({'id': id, 'network_address': network_address_id, 'port': port, 'tls_profiles': tls_profiles,
                      'whitelist_ips': wl_ips, 'max_src': max_src, 'max_rate': max_rate});
    });
    $('#listeners').val(JSON.stringify(listeners));

    if( $('#id_mode').val() == "http" ) {
      var headers = new Array();
      $('#header_table tbody tr').each(function(index, tr) {
        var id = tr.children[0].innerHTML;
        var enabled = $(tr.children[1].children[0]).is(":checked");
        var type = tr.children[2].children[0].value;
        var action = tr.children[3].children[0].value;
        var header_name = tr.children[4].children[0].value;
        var match = tr.children[5].children[0].value;
        var replace = tr.children[6].children[0].value;
        var condition_action = tr.children[7].children[0].value;
        var condition = tr.children[8].children[0].value;
        headers.push({'id': id, 'enabled': enabled, 'type': type, 'action': action, 'header_name': header_name,
                      'match': match, 'replace': replace, 'condition_action': condition_action,
                      'condition': condition});
      });
      $('#headers').val(JSON.stringify(headers));
    }
    var reputation_ctxs = new Array();
    $('#reputationctx_table tbody tr').each(function(index, tr) {
      var enabled = $(tr.children[0].children[0]).is(":checked");
      var reputation_ctx = tr.children[1].children[0].value;
      var arg_field = tr.children[2].children[0].value;
      var dst_field = tr.children[3].children[0].value;
      reputation_ctxs.push({'enabled': enabled, 'reputation_ctx': reputation_ctx, 'arg_field': arg_field, 'dst_field': dst_field});
    });
    $('#reputation_contexts').val(JSON.stringify(reputation_ctxs));

    var keep_source_fields = {};
    $('#keep_source_fields_table tbody tr').each(function(index, tr) {
      var field_name = tr.children[0].children[0].value;
      var field_value = tr.children[1].children[0].value;
      var keep_source = tr.children[2].children[0].checked;
      keep_source_fields[field_value] = {'field_name': field_name, 'keep_source': keep_source};
    });
    $('#keep_source_fields').val(JSON.stringify(keep_source_fields));

    /* Enable button before posting, it won't be in post data otherwize */
    $('#id_enable_logging').prop('disabled', false);
    // event.preventDefault();
  });

  $('.tag-editor').css({"min-width": "100px"});


  $('#add_log_fwd_entry').on('click', function(e) {
    $('#log_forwarders_table').append(log_om_table_td);
    refresh_table_events();
    $('#log_forwarders_table').trigger('change');
  });


  $('#add_reputationctx_entry').on('click', function(e) {
    $('#reputationctx_table').append(reputationctx_form_td);
    refresh_table_events();
    $('#reputationctx_table').trigger('change');
  });


  /* Returns log_forwarders_table tr rules as string */
  function get_forwarders_table_rules() {
    var result = "";
    /* Loop over log_forwarders MultipleSelect selected options */
    $('#id_log_forwarders > option:selected').each(function() {
      result += "{{" + $(this).text() + "}} \n";
    });
    /* Loop over data table */
    $('#log_forwarders_table > tbody > tr').each(function() {
      /* Get select action(s) */
      var actions = $(this).children('td:eq(4)').children('select').children('option:selected');
      /* If no action, no need to display element */
      if( actions.length > 0 ) {
        /* Condition -> first td + select input */
        var condition = $(this).children('td:eq(0)').children('select').val();
        result += condition + "( ";
        var name = $(this).children('td:eq(1)').children('select').val();
        result += name + " ";
        var operator = $(this).children('td:eq(2)').children('select').val();
        result += operator + " ";
        var value = $(this).children('td:eq(3)').children('input').val()
        result += value + " ) then { \n";

        actions.each( function(index, item) {
          result += "        {{"+item.text+"}} \n";
        });
        result += "} \n";
      }
    });
    return result;
  }

  function refresh_log_forwarders(log_fwds) {
    // If mongodb forwarder selected but stock_logs_locally not enabled
    if( ( ($.inArray("1", log_fwds) !== -1) && ( !$('#stock_logs_locally').is(':checked') ) ) || ( ($.inArray("1", log_fwds) === -1) && ( $('#stock_logs_locally').is(':checked') ) ) ) {
      // Enable it
      $('#stock_logs_locally').click();
    } else if( ( ($.inArray("2", log_fwds) !== -1) && ( !$('#archive_logs').is(':checked') ) ) || ( ($.inArray("2", log_fwds) === -1) && ( $('#archive_logs').is(':checked') ) ) ) {
      $('#archive_logs').click();
    }
    var result = get_forwarders_table_rules();
    $('#id_log_condition').val(result);
  }

  /* Format log_forwarders_table as text and render in textArea */
  $('#log_forwarders_table').on('change', function(e) {
    var result = get_forwarders_table_rules();
    $('#id_log_condition').val(result);
  });
  /* Format log_forwarders as text and render in textArea */
  $('#id_log_forwarders').on('change', function(e) {
    refresh_log_forwarders($(this).val());
  });

  /* Initialize all custom fields */
  refresh_table_events();

}); // end of function()

$(function(){
    var elems = Array.prototype.slice.call(document.querySelectorAll('.js-switch'));
    elems.forEach(function(html) {
      var switchery = new Switchery(html);
    });
    redrawSwitch('id_enable_logging');
    $("#id_kafka_options").tagsinput({
                    freeInput: true,
                    typeaheadjs: {
                        minLength: 0,
                        freeInput: true,
                        name: "choices",
                        source: function(query, syncResults) {
                            syncResults([
                                "sasl.mechanism=SCRAM-SHA-512",
                                "sasl.mechanism=SCRAM-SHA-256",
                                "security.protocol=SASL_PLAINTEXT",
                                "security.protocol=PLAINTEXT",
                                "security.protocol=SASL_SSL",
                                "security.protocol=SSL",
                                "sasl.username=xxx",
                                "sasl.password=xxx",
                            ]);
                        }
                    }
                });
})

var custom_operations_vue = new Vue({
  el: '#custom_operations_vue',
  delimiters: ['${', '}'],
  data: {
    or_lines: [],
    rule: ""
  },

  methods: {
    is_selected: function (type, line, value) {
      return line[type] === value ? "selected" : "";
    },

    generate_id: function () {
      return Math.random().toString(36).substring(5);
    },

    render_config: function () {
      if (jQuery.isEmptyObject(this.or_lines)) return;

      let result = "";
      let has_or_lines = false;

      for (var j in this.or_lines) {
        var or_line = this.or_lines[j];
        if (!or_line.lines.length) continue;

        has_or_lines = true;

        result += "# Block " + (parseInt(j) + 1) + "\n";

        let conditions = [];
        for (var i in or_line.lines) {
          var and_line = or_line.lines[i];
          var condition = and_line.condition;
          var condition_var = and_line.condition_variable;
          var condition_val = and_line.condition_value;
          var action = and_line.action;
          var result_var = and_line.result_variable;
          var result_val = and_line.result_value;

          let cond_str = "";
          let comment = "";

          switch (condition) {
            case "always":
              cond_str = "";
              comment = "#always";
              break;
            case "exists":
              cond_str = `exists(${condition_var})`;
              comment = "#exists";
              break;
            case "not exists":
              cond_str = `not exists(${condition_var})`;
              comment = "#not exists";
              break;
            case "equals":
              cond_str = `${condition_var} == "${condition_val}"`;
              comment = "#equals";
              break;
            case "iequals":
              cond_str = `ieq(${condition_var}, "${condition_val}")`;
              comment = "#iequals";
              break;
            case "contains":
              cond_str = `${condition_var} contains "${condition_val}"`;
              comment = "#contains";
              break;
            case "icontains":
              cond_str = `icontains(${condition_var}, "${condition_val}")`;
              comment = "#icontains";
              break;
            case "regex":
              cond_str = `re_match(${condition_var}, "${condition_val}")`;
              comment = "#regex";
              break;
            case "iregex":
              cond_str = `re_match_i(${condition_var}, "${condition_val}")`;
              comment = "#iregex";
              break;
            default:
              cond_str = "";
              comment = "#unknown";
          }

          let action_str = "";
          switch (action) {
            case "set":
              action_str = `set ${result_var} = "${result_val}"`;
              break;
            case "unset":
              action_str = `unset ${result_var}`;
              break;
            case "drop":
              action_str = "drop";
              break;
            default:
              action_str = "noaction";
          }

          conditions.push({
            condition: cond_str,
            action: action_str,
            comment: comment
          });
        }

        for (let i = 0; i <= conditions.length - 1; i++) {
          if (i !== 0) {
            result += "} else "
          }
          if (conditions[i].condition === "") {
            if (conditions.length !== 1) {
              result += `{ ${conditions[i].comment}\n  `;
            }
          } else {
            result += `if ${conditions[i].condition} then { ${conditions[i].comment}\n  `;
          }
          result += `${conditions[i].action}\n`;
        }
        if (conditions.length !== 1 || conditions[0].condition !== "") {
          result += "}\n";
        }
      }

      if (!has_or_lines) {
        result = "# No rules defined\n";
      }

      this.rule = result
        .split('\n')
        .map(line => line)
        .join('\n');
    },

    get_or_index: function (or_id) {
      for (let i in this.or_lines) {
        if (this.or_lines[i].pk === or_id) return i;
      }
      return -1;
    },

    check_config: function (and_line) {
      let errors = [];

      if (!and_line.condition) errors.push('condition');

      if (and_line.condition !== "always" && !and_line.condition_variable) errors.push('condition_variable');
      if (!['always', 'exists', 'not exists'].includes(and_line.condition) && !and_line.condition_value) errors.push('condition_value');

      if (!and_line.action) errors.push('action');

      if (['set', 'unset'].includes(and_line.action) && !and_line.result_variable) errors.push('result_variable');
      if (and_line.action === 'set' && !and_line.result_value) errors.push('result_value');

      return errors.length ? errors : null;
    },

    render_error: function (errors, input) {
      if (!input) return errors ? "<i class='fas fa-exclamation-triangle fa-2x'></i>" : "";
      return errors !== null && errors.includes(input) ? "<i class='fas fa-exclamation-triangle'></i>&nbsp;&nbsp;&nbsp;" + gettext('This input is mandatory') : "";
    },

    render_class_and_line: function (error) {
      return error ? "and_line and_line_error" : "and_line";
    },

    add_or: function () {
      let pk = this.generate_id();
      this.or_lines.push({
        pk: pk,
        lines: []
      });
      this.render_config();
      this.add_and(pk);
    },

    remove_or: function (or_id) {
      let index = this.get_or_index(or_id);
      if (index !== -1) {
        this.or_lines.splice(index, 1);
        this.render_config();
      }
    },

    render_id: function (or_index, and_index) {
      return `and_line_${or_index}_${and_index}`;
    },

    reconstruct_rules: function () {
      var self = this;
      $('.condition_block').each(function () {
        var or_index = $(this).data('index');
        $(this).find('.and_line').each(function () {
          var and_index = $(this).data('index');
          var and_line = self.or_lines[or_index].lines[and_index];

          and_line.condition = $(`#and_line_${or_index}_${and_index} .condition`).val();
          and_line.condition_variable = $(`#and_line_${or_index}_${and_index} .condition_variable`).val();
          and_line.condition_value = $(`#and_line_${or_index}_${and_index} .condition_value`).val();
          and_line.action = $(`#and_line_${or_index}_${and_index} .action`).val();
          and_line.result_variable = $(`#and_line_${or_index}_${and_index} .result_variable`).val();
          and_line.result_value = $(`#and_line_${or_index}_${and_index} .result_value`).val();

          and_line.error = self.check_config(and_line);
          self.or_lines[or_index].lines[and_index] = and_line;
        });
      });
    },

    add_and: function (or_id) {
      var self = this;
      let index = self.get_or_index(or_id);
      self.reconstruct_rules();

      this.or_lines[index].lines.push({
        condition: "always",
        condition_variable: "",
        condition_value: "",
        action: "set",
        result_variable: "",
        result_value: "",
        error: null
      });

      this.$nextTick(() => {
        $('.action').on('change', function () { self.render_config(); });
        $('.condition').on('change', function () { self.render_config(); });
        $('.condition_variable, .condition_value, .result_variable, .result_value').on('keyup', function () { self.render_config(); });
      });

      this.render_config();
    },

    remove_and: function (or_id, and_index) {
      let index = this.get_or_index(or_id);
      if (index !== -1) {
        this.or_lines[index].lines.splice(and_index, 1);
        this.render_config();
      }
    },

    dragStart(e, or_index, and_index) {
      e.dataTransfer.setData('text/plain', JSON.stringify({ or_index, and_index }));
      e.dataTransfer.effectAllowed = 'move';
      document.querySelectorAll('.and_line').forEach(el => el.classList.add('dragging'));
      document.querySelector(`#and_line_${or_index}_${and_index}`)?.classList.add('dragging-active');
    },

    dragEnter(e) {
      e.dataTransfer.dropEffect = 'move';
    },

    dragDrop(e, target_or_index, target_and_index) {
      e.preventDefault();
      const data = e.dataTransfer.getData('text/plain');
      if (!data) return;

      const { or_index, and_index } = JSON.parse(data);

      if (or_index === target_or_index && and_index === target_and_index) return;

      if (or_index !== target_or_index) return;

      const lines = this.or_lines[or_index].lines;

      const draggedLine = lines.splice(and_index, 1)[0];

      lines.splice(target_and_index, 0, draggedLine);

      this.$nextTick(() => {
        this.render_config();
        this.reconstruct_rules();
      });
    },

    save_form: function () {
      var txt = $('#save_form_btn').html();
      $('#save_form_btn').html('<i class="fa fa-spinner fa-spin"></i>');
      $('#save_form_btn').prop('disabled', 'disabled');

      var self = this;
      self.reconstruct_rules();
      self.render_config();

      for (var or_line of self.or_lines) {
        for (var and_line of or_line.lines) {
          if (self.check_config(and_line)) return false;
        }
      }

      var data = {
        or_lines: JSON.stringify(self.or_lines),
        rule: self.rule,
        name: $('#id_name').val(),
        enabled: $('#id_enabled').is(':checked')
      };

      $.ajax({
        url: '',
        data: data,
        type: "POST",
        success: function (response) {
          $('#save_form_btn').html(txt);
          $('#save_form_btn').prop('disabled', '');
          if (check_json_error(response)) {
            notify('success', gettext('Saved successfully'));
            setTimeout(() => window.location.href = frontend_list_uri, 1000);
          }
        },
        error: function () {
          $('#save_form_btn').html(txt);
          $('#save_form_btn').prop('disabled', '');
        }
      });
    }
  },

  mounted: function () {
    var self = this;
    // if (pk_frontend) {
    //   $.post(frontend_get_uri, {'pk': pk_frontend}, function(response) {
    //     if (check_json_error(response)) {
    //       self.or_lines = JSON.parse(response.frontend.rules);
    //       self.render_config();
    //     }
    //   });
    // } else {
    self.add_or();
    // }
  },

  updated: function () {
    $('.condition_block').each(function () {
      var index = $(this).data('index');
      $(this).css('marginLeft', index * 50 + "px");
    });
  }
});