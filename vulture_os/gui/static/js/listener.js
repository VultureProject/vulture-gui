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

/* Redraw a switch to take new properties into account */
function redrawSwitch(elem) {
  if (elem === undefined) return;
  elem.removeAttribute('readonly');
  while(elem.nextElementSibling) elem.nextElementSibling.remove();
  Switchery(elem);
}

function editing_existing_object() {
  return !window.location.href.endsWith("/edit/")
}

$(function() {

  var initial_test_button_text = $('#test_api_parser').html();

  function fetch_api_collector_form(type_, data) {
    PNotify.removeAll();

    let btn = $('#test_api_parser');
    $(btn).html('<i class="fa fa-spinner fa-spin"></i>');
    $(btn).prop('disabled', true);

    $.get(
      fetch_api_collector_form_uri.replace('collector_name', type_),
      data
    )
    .done(function(response){
      //TODO ensure objects and JS is refreshed to show correctly
      $('#api_collector_form_div').html(response);
      // Refresh tags-input bootstrap fields after their import in the DOM
      $('#api_collector_form_div').find('[data-role="tagsinput"]').each(function(index){
        $( this ).tagsinput();
      });
    })
    .fail(function(response){
      notify('error', response.status, "Could not load collector's details");
    })
    .always(function(){
      $(btn).prop('disabled', false);
      $(btn).html(initial_test_button_text);
      refresh_api_parser_type(type_);
    })
  }

  function get_api_parser_data() {
    let data = {
      api_parser_type: $('#id_api_parser_type').val(),
    };

    $('#api_collector_form_div input, #api_collector_form_div select').each(function(){
      let name = $(this).attr('name');
      switch($(this).attr('type')){
        case "checkbox":
          data[name] = $(this).is(':checked');
          break;
        default:
          if (name === "x509_cert") {
            if (data['verify_ssl'] === true && !api_parser_blacklist.includes(data.api_parser_type))
              data[name] = $(this).val();
          }
          else
            data[name] = $(this).val();
          break;
      }
    })

    return data;
  }

  function refresh_api_parser_type(type_){
    $('.api_collectors_row').hide();

    if ($('#id_mode').val() === "log" && $('#id_listening_mode').val() === "api") {
      $('#id_node').hide();
      $(`#collector_${type_.replaceAll('_', '')}collectorform_row`).show();

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
      initial_fetch_data_button_text = $(btn).html();
      $(btn).html('<i class="fa fa-spinner fa-spin"></i>');
      $(btn).prop('disabled', true);

      var target = $(this).data('target');
      var type_target = $(this).data('type');

      var data = get_api_parser_data();

      $('#'+target).empty();

      $.post(
        fetch_frontend_api_parser_data_uri,
        data,
      )
      .done(function(response){
        if (!check_json_error(response))
            return;

          var data = response.data;
          if (type_target == "select"){
            for (var i in data)
              $('#'+target).append(new Option(data[i], data[i]))
          }
      })
      .fail(function(response){
        notify('error', response.status, response.responseText);
        fetch_api_collector_form($('#id_api_parser_type').val(), data);
      })
      .always(function(){
        $(btn).prop('disabled', false);
        $(btn).html(initial_fetch_data_button_text);
      })
    })

    $('#test_api_parser').unbind('click');
    $('#test_api_parser').on('click', function(){
      PNotify.removeAll();
      if($('#id_api_parser_type').val() == "") {
        notify('error', gettext('Error'), gettext('Select an API Parser Type'))
        return
      }

      var btn = this;
      $(btn).html('<i class="fa fa-spinner fa-spin"></i>');
      $(btn).prop('disabled', true);

      var data = get_api_parser_data();

      $.post(
        test_frontend_apiparser_uri,
        data,
      )
      .done(function(response){
        if (!check_json_error(response)){
          $('#id_api_parser_has_been_tested').val('0');
          return;
        }
        var data = response.data;
        $('#id_api_parser_has_been_tested').val('1');
        $('#modal-test-apiparser-body').html('<pre>' + JSON.stringify(data, null, 4) + "</pre>");
        $('#modal-test-apiparser').modal('show');

      })
      .fail(function(response){
        notify('error', response.status, response.responseText);
        fetch_api_collector_form($('#id_api_parser_type').val(), data);
      })
      .always(function(){
        $(btn).prop('disabled', false);
        $(btn).html(initial_test_button_text);
      })
    })

    if ($('#id_mode').val() === "log" && $('#id_listening_mode').val() === "api") {
      $('#id_use_proxy').on('change', function(e){
        if ($(this).is(':checked')) {
          $(`#collector_custom_proxy`).show();
        } else {
          $(`#collector_custom_proxy`).hide();
        }
      }).trigger('change');
      $('#id_verify_ssl').on('change', function(e){
        if ($(this).is(':checked') && !api_parser_blacklist.includes(type_)) {
          $(`#collector_x509_cert`).show();
        } else {
          $(`#collector_x509_cert`).hide();
        }
      }).trigger('change');
      redrawSwitch($('#id_use_proxy')[0]);
      redrawSwitch($('#id_verify_ssl')[0]);
      $('#id_x509_cert').select2();
    }
  }

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
      redrawSwitch($('#id_redis_use_local')[0]);
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
    if (mode === "filebeat") {
      $('.api-mode').hide();
      $('.kafka-mode').hide();
      $('.redis-mode').hide();
      $('.file-mode').hide();
      if ($('#id_filebeat_config').val().includes("%ip%")) {
        $('.network-mode').show();
        $('.haproxy-conf').show();
      } else {
        $('.network-mode').hide();
        $('.haproxy-conf').hide();
      }
      $('.filebeat-mode').show();
    } else if (mode === "log" && listening_mode === "file") {
      $('.network-mode').hide();
      $('.api-mode').hide();
      $('.kafka-mode').hide();
      $('.redis-mode').hide();
      // ALWAYS put show at last
      $('.file-mode').show();
    } else if (mode === "log" && listening_mode === "api") {
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

  /* Show haproxy-only fields, or hide them */
  function show_custom_conf(mode, listening_mode, filebeat_listening_mode) {
    /* If it is an UDP mode only => HAProxy is useless */
    if (mode === "tcp" || mode === "http" ||
      (mode === "log" && ["tcp", "tcp,udp", "relp"].includes(listening_mode)) ||
      (mode === "filebeat" && $('#id_filebeat_config').val().includes("%ip%"))) {
      $('.haproxy-conf').show();
    } else {
      $('.haproxy-conf').hide();
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
    if ((mode === "log" && ["file", "api", "kafka", "redis"].includes(listening_mode)) ||
      (mode === "filebeat" && !$('#id_filebeat_config').val().includes("%ip%"))) {
      $('#node-div').show();
    } else {
      $('#node-div').hide();
    }
  }

  /* Show filebeat input field, or hide it, depending on chosen filebeat module */
  function show_filebeat_input(mode, filebeat_module) {
    if ((mode === "filebeat" && filebeat_module === "_custom")) {
      $('#filebeat-input-div').show();
    } else {
      $('#filebeat-input-div').hide();
    }
  }

  function refresh_input_logs_type(mode, listening_mode, filebeat_listening_mode){
    var first = true;
    if((mode === "log") || (mode === "filebeat") ){
      $('#ruleset-div').show();
    }
    else {
      $('#ruleset-div').hide();
      if(mode === "log" && listening_mode === "api"){
        // Bind API inputs
        $("#tab_log_settings input").each(function(){
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
    } else {
      $('#api_parser_custom_proxy').hide();
    }
  }).trigger('change');

  // we need to trigger it first to activate test button
  refresh_api_parser_type($('#id_api_parser_type').val());

  $('#id_api_parser_type').on('change', function(){
    if($(this).val() == "") {
      $('#test_api_parser').prop("disabled", true);
    } else {
      $('#test_api_parser').prop("disabled", false);
      fetch_api_collector_form($(this).val());
    }
  });

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
  var last_ruleset = $('#id_ruleset').val();
  $('#id_mode').on('change', function(event) {
    var mode = $(this).val();
    $('.http-mode').hide();
    $('.tcp-mode').hide();
    $('.log-mode').hide();
    $('.filebeat-mode').hide();
    $('.'+mode+'-mode').show();

    //get current ruleset value to rollback at next mode change
    var new_last_ruleset = $('#id_ruleset').val();
    // Set old value for ruleset
    $('#id_ruleset').val(last_ruleset).trigger('change');
    last_ruleset = new_last_ruleset;

    /* If mode = LOG / Filebeat => Activate logging automatically */
    var log_enabled = $('#id_enable_logging').is(":checked");
    if(mode === "log") {
      if(!log_enabled) {
        last_enable_log = log_enabled;
        $('#id_enable_logging').trigger('click');
      }
      $('#id_enable_logging').prop("disabled", true);
      if( $('#stock_logs_locally').is(':checked') ) {
        $('#stock_logs_locally').click();
      }
      refresh_input_logs_type(mode, $('#id_listening_mode').val(), $('#id_filebeat_listening_mode').val());
    } else if(mode === "filebeat") {
      if(!log_enabled) {
        last_enable_log = log_enabled;
        $('#id_enable_logging').trigger('click');
      }
      $('#id_enable_logging').prop("disabled", true);
      refresh_filebeat_config();
      refresh_filebeat_ruleset();
    } else if ( mode === "http" || mode === "tcp" ) {
      refresh_http();
      $('#id_enable_logging').prop("disabled", false);
      if( last_enable_log != log_enabled )
        $('#id_enable_logging').trigger('click');
    }

    $('#id_enable_logging').trigger("change");
    refresh_ruleset($('#id_ruleset').val());

    show_custom_conf(mode, $('#id_listening_mode').val(), $('#id_filebeat_listening_mode').val());
    show_tcp_conf(mode, $('#id_listening_mode').val(), $('#id_filebeat_listening_mode').val());
    show_network_conf(mode, $('#id_listening_mode').val(), $('#id_filebeat_listening_mode').val());
    show_redis_conf(mode, $('#id_listening_mode').val(), $('#id_filebeat_listening_mode').val());
    show_node(mode, $('#id_listening_mode').val(), $('#id_filebeat_listening_mode').val());
    show_filebeat_input(mode, $('#id_filebeat_module').val());
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
    redrawSwitch($('#id_enable_logging')[0]);
  }).trigger("change");

  $('#id_darwin_policies').on("change", function(e) {
    var policy = $(this).val();
    show_darwin_mode(policy);
  }).trigger('change');

  var last_filebeat_module = $('#id_filebeat_module').val();

  function refresh_filebeat_config() {
    // Save current local config for this module, to show it again if re-selected during edition
    if($('#id_filebeat_config').val()) {
      filebeat_config[last_filebeat_module] = $('#id_filebeat_config').val();
    }
    // Update config field with related module configuration
    $('#id_filebeat_config').val(filebeat_config[$("#id_filebeat_module").val()]);
    $('#id_filebeat_config').trigger('change');
  }

  function refresh_filebeat_ruleset() {
    // Do NOT update ruleset value on existing configurations (allows override during initial creation)
    if(!editing_existing_object()) {
      filebeat_module = $('#id_filebeat_module').val();
      if ($("#id_ruleset option[value='beat_" + filebeat_module + "-ecs']").length > 0) {
        $('#id_ruleset').val("beat_" + filebeat_module + "-ecs").trigger('change');
      } else if ($("#id_ruleset option[value='beat_" + filebeat_module + "']").length > 0) {
        $('#id_ruleset').val("beat_" + filebeat_module).trigger('change');
      } else {
        $('#id_ruleset').val('generic_json').trigger('change');
      }
    }
  }

  $('#id_filebeat_module').on("change", function(e) {
    show_filebeat_input($('#id_mode').val(), $(this).val());
    refresh_filebeat_config();
    refresh_filebeat_ruleset();
    // Update value for next comparison
    last_filebeat_module = $(this).val();
  })

  $('#id_filebeat_config').on("change", function(e) {
    show_network_conf($('#id_mode').val(), $('#id_listening_mode').val(), $('#id_filebeat_listening_mode').val());
    show_redis_conf($('#id_mode').val(), $('#id_listening_mode').val(), $('#id_filebeat_listening_mode').val());
    show_node($('#id_mode').val(), $('#id_listening_mode').val(), $('#id_filebeat_listening_mode').val());
  }).trigger('change');

  /* Show log_condition_failure depending on mode and ruleset */
  function show_log_condition_failure() {
    if(['log', 'filebeat'].includes($('#id_mode').val()) && !['raw_to_json'].includes($('#id_ruleset').val())) {
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
        notify('error', gettext('Error'), gettext('Test your API configuration before saving this frontend'));
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

    let custom_actions = new Array();
    custom_actions_vue.reconstruct_configs();
    for (let condition_block of custom_actions_vue.condition_blocks) {
      let condition_block_array = new Array();
      for (let condition_line of condition_block.lines) {
        if (custom_actions_vue.validate_condition_line(condition_line).length > 0) {
          notify('error', gettext('Error'), gettext('Error identified in custom operations tab'));
        };
        condition_block_array.push({
          'condition': condition_line.condition,
          'condition_variable': condition_line.condition_variable,
          'condition_value': condition_line.condition_value,
          'action': condition_line.action,
          'result_variable': condition_line.result_variable,
          'result_value': condition_line.result_value
        });
      }
      custom_actions.push(condition_block_array)
    }
    $('#id_custom_actions').val(JSON.stringify(custom_actions));

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
      redrawSwitch(html);
    });
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

var custom_actions_vue = new Vue({
  el: '#custom_actions_vue',
  delimiters: ['${', '}'],
  data: {
    condition_blocks: custom_actions.length > 0 ? custom_actions : [],
    global_errors: []
  },

  methods: {
    is_selected: function (type, line, value) {
      return line[type] === value ? "selected" : "";
    },

    generate_id: function () {
      return Math.random().toString(36).substring(5);
    },

    get_block_index: function (block_id) {
      for (let i in this.condition_blocks) {
        if (this.condition_blocks[i].pk === block_id) return i;
      }
      return -1;
    },

    add_condition_block: function () {
      let pk = this.generate_id();
      this.condition_blocks.push({
        pk: pk,
        lines: []
      });
      this.add_line(pk);
    },

    remove_condition_block: function (block_id) {
      let index = this.get_block_index(block_id);
      if (index !== -1) {
        this.condition_blocks.splice(index, 1);
      }
    },

    add_line: function (block_id) {
      let index = this.get_block_index(block_id);

      this.condition_blocks[index].lines.push({
        condition: "always",
        condition_variable: "",
        condition_value: "",
        action: "",
        result_variable: "",
        result_value: "",
        errors: []
      });

      this.reconstruct_configs();

      this.$nextTick(() => {
        $('.action, .condition').on('change', () => { this.reconstruct_configs(); });
        $('.condition_variable, .condition_value, .result_variable, .result_value').on('blur', () => { this.reconstruct_configs(); });
      });
    },

    remove_line: function (block_id, line_index) {
      let index = this.get_block_index(block_id);
      if (index !== -1) {
        this.condition_blocks[index].lines.splice(line_index, 1);
      }
    },

    render_error: function (errors, input) {
      if (!input) return errors ? "<i class='fas fa-exclamation-triangle fa-2x'></i>" : "";
      if (errors !== null && errors.length > 0) {
        for (error of errors) {
          if (error.field === input) {
            return "<i class='fas fa-exclamation-triangle'></i>&nbsp;&nbsp;&nbsp;" + error.message;
          }
        }
        return errors.includes(input) ? "<i class='fas fa-exclamation-triangle'></i>&nbsp;&nbsp;&nbsp;" + gettext('Error with this input') : "";
      }
      return "";
    },

    render_class_condition_line: function (errors) {
      return errors !== null && errors.length > 0 ? "and_line_error" : "condition_line";
    },

    render_id: function (block_index, line_index) {
      return `condition_line_${block_index}_${line_index}`;
    },

    validate_condition_line: function (condition_line) {
      let errors = [];

      if (!condition_line.condition)
        errors.push({field: 'condition', message: gettext('This field is mandatory')});

      if (!condition_line.condition_variable) {
        if (condition_line.condition !== "always")
          errors.push({field: 'condition_variable', message: gettext('This field is mandatory')});
      } else if (condition_line.condition_variable[0] !== "$")
        errors.push({field: 'condition_variable', message: gettext('Invalid variable name')});

      if (!condition_line.condition_value) {
        if (!['always', 'exists', 'not exists'].includes(condition_line.condition))
          errors.push({field: 'condition_value', message: gettext('This field is mandatory')});
      } else if (condition_line.condition_value[0] === "$")
        errors.push({field: 'condition_value', message: gettext('Cannot use a variable here')});

      if (!condition_line.action)
        errors.push({field: 'action', message: gettext('This field is mandatory')});

      if (!condition_line.result_variable) {
        if (['set', 'unset'].includes(condition_line.action))
          errors.push({field: 'result_variable', message: gettext('This field is mandatory')});
      } else if (condition_line.result_variable[0] !== "$")
        errors.push({field: 'result_variable', message: gettext('Invalid variable name')});

      if (condition_line.action === 'set' && !condition_line.result_value)
        errors.push({field: 'result_value', message: gettext('This field is mandatory')});

      return errors.length ? errors : [];
    },

    validate_condition_block: function (condition_block) {
      const lines = condition_block.lines;
      this.global_errors = [];
      let errors = [];
      let always_count = 0;

      for (let i = 0; i < lines.length; i++) {
        if (lines[i].condition === 'always') {
          always_count++;

          if (always_count > 1) {
            this.global_errors.push({
              message: gettext('Only one "Always" condition is allowed per group')
            });
            lines[i].errors.push({
              field: 'condition',
              message: gettext('Only one "Always" allowed')
            });
          }
          if (always_count >= 1 && i !== lines.length - 1) {
            this.global_errors.push({
              message: gettext('"Always" condition must be the last rule in the group')
            });
            lines[i].errors.push({
              field: 'condition',
              message: gettext('This line should go down')
            });
          }
        }
      }
      return errors;
    },

    reconstruct_configs: function () {
      var self = this;

      $('.condition_group').each(function () {
        let block_index = $(this).data('index');
        $(this).find('.condition_line').each(function () {
          let line_index = $(this).data('index');

          if (self.condition_blocks[block_index] !== undefined) {
            let condition_line = self.condition_blocks[block_index].lines[line_index];
            if (condition_line !== undefined) {
              let query_id = self.render_id(block_index, line_index);

              condition_line.condition = $(`#${query_id} .condition`).val();
              condition_line.condition_variable = $(`#${query_id} .condition_variable`).val();
              condition_line.condition_value = $(`#${query_id} .condition_value`).val();
              condition_line.action = $(`#${query_id} .action`).val();
              condition_line.result_variable = $(`#${query_id} .result_variable`).val();
              condition_line.result_value = $(`#${query_id} .result_value`).val();

              condition_line.errors = self.validate_condition_line(condition_line);
              self.condition_blocks[block_index].lines[line_index] = condition_line;
            }
          }
        });
        if (self.condition_blocks[block_index] !== undefined &&
          self.condition_blocks[block_index].lines !== undefined &&
          self.condition_blocks[block_index].lines.length > 0) {
            self.validate_condition_block(self.condition_blocks[block_index]);
        }
      });
    },

    dragStart(e, block_index, line_index) {
      let mainnav_hidden = $('#container').hasClass('mainnav-sm');
      let max_x = 90 + 220 * !mainnav_hidden + 55 * mainnav_hidden;
      if (['INPUT', 'SELECT'].includes(e.target.tagName) || e.x > max_x) {
        e.preventDefault();
        return;
      }

      e.dataTransfer.setData('text/plain', JSON.stringify({ block_index, line_index }));
      e.dataTransfer.effectAllowed = 'move';
      document.querySelectorAll('.condition_line').forEach(el => el.classList.add('dragging'));
      document.querySelector(`#condition_line_${block_index}_${line_index}`)?.classList.add('dragging-active');
    },

    dragEnter(e) {
      e.dataTransfer.dropEffect = 'move';
    },

    dragDrop(e, target_block_index, target_line_index) {
      e.preventDefault();
      const data = e.dataTransfer.getData('text/plain');
      if (!data) return;

      const { block_index, line_index } = JSON.parse(data);
      if (block_index === target_block_index && line_index === target_line_index) return;
      if (block_index !== target_block_index) return;

      const lines = this.condition_blocks[block_index].lines;
      const draggedLine = lines.splice(line_index, 1)[0];
      lines.splice(target_line_index, 0, draggedLine);

      this.$nextTick(() => {
        this.reconstruct_configs();
      });
    },
  },

  mounted: function () {
    this.$nextTick(() => {
      $('.action, .condition').on('change', () => { this.reconstruct_configs(); });
      $('.condition_variable, .condition_value, .result_variable, .result_value').on('blur', () => { this.reconstruct_configs(); });
    });
    this.reconstruct_configs();
  },
});