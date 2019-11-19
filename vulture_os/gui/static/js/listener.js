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



function refresh_api_parser_type(type_){
    $('.api_clients_row').hide();
    if ($('#id_mode').val() === "log" && $('#id_listening_mode').val() === "api"){
      $('#api_'+type_+"_row").show();
    }

    if (type_ === "elasticsearch"){
      $('#id_elasticsearch_auth').on('change', function(){
        if ($(this).is(':checked'))
          $('.elasticsearch_auth').show();
        else
          $('.elasticsearch_auth').hide();
      }).trigger('change')

      $('#get_elasticsearch_index').on('click', function(){
        var btn = this;
        var txt = $(btn).html();
        $(btn).html('<i class="fa fa-spinner fa-spin"></i>');
        $(btn).prop('disabled', true);

        var data = {
          type_parser: "elasticsearch",
          els_host: $('#id_elasticsearch_host').val(),
          els_verify_ssl: $('#id_elasticsearch_verify_ssl').is(":checked"),
          els_auth: $('#id_elasticsearch_auth').is(":checked"),
          els_username: $('#id_elasticsearch_username').val(),
          els_password: $('#id_elasticsearch_password').val(),
          els_index: $('#id_elasticsearch_index').val()
        }

        $.post(
          test_frontend_apiparser_uri,
          data,

          function(response){
            $(btn).prop('disabled', false);
            $(btn).html(txt);
            if (!check_json_error(response)){
              $('#elasticsearch_check_status').val('0');
              return;
            }

            var stats = response.stats;
            $('#elasticsearch_check_status').val('1');
            $('#modal-test-apiparser-body').html('<pre>' + JSON.stringify(stats, null, 4) + "</pre>");
            $('#modal-test-apiparser').modal('show');
          }
        )
      })
    }
  }




$(function() {

  toggle_impcap_filter_type();

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
  function show_network_conf(mode, listening_mode) {
    /* If it is an rsyslog / File only conf */
    if(mode === "log" && listening_mode === "file") {
      $('.network-mode').hide();
      $('.file-mode').show();
    } else if (mode === "log" && listening_mode === "api"){
      $('.network-mode').hide();
      $('.file-mode').hide();
      $('.api-mode').show();
    } else {
      $('.network-mode').show();
      $('.file-mode').hide();
      $('.api-mode').hide();
    }
  }

  /* Show rsyslog only fields, or hide them */
  function show_custom_conf(mode, listening_mode) {
    /* If it is an Rsyslog only conf */
    if( (mode === "log" && (listening_mode === "udp" || listening_mode === "file" || listening_mode === "api")) || mode === "impcap") {
      $('.haproxy-conf').hide();
    } else {
      $('.haproxy-conf').show();
    }
  }


  /* Show fields, or hide them, depending on chosen listening mode */
  function show_listening_mode(mode, listening_mode) {
    /* If listening mode is TCP, show according options */
    if( mode == "log" && listening_mode === "tcp" ) {
      $('.listening-tcp').show();
    } else {
      $('.listening-tcp').hide();
    }
  }

  function refresh_input_logs_type(listening_mode){
    var first = true;
    $('#id_ruleset').prop('disabled', false)
    if (listening_mode === "api"){
      $('#id_ruleset').val('generic_json').trigger('change');
      $('#id_ruleset').prop('disabled', true)
    }
  }

  $('#id_api_parser_type').on('change', function(){
    refresh_api_parser_type($(this).val());
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

  /* Do NOT touch this method ! */
  var filter_displayed = "false";
  /* Show impcap_filter depending on what filter_type is chosen */
  function toggle_impcap_filter_type() {
    let impcap_filter_type = $('#id_impcap_filter_type').val();
    if( impcap_filter_type === "custom" ) {
      $('#id_impcap_filter').prop("readonly", false);
      $('#id_impcap_filter').val("");
    } else {
      $('#id_impcap_filter').prop("readonly", true);
      $('#id_impcap_filter').val($('#id_impcap_filter_type').val());
      toggle_impcap_filter();
    }
  }
  $('#id_impcap_filter_type').on('change', toggle_impcap_filter_type);


  /* Show darwin option depending on enable checkbox */
  function toggle_impcap_darwin() {
    if( $('#id_enable_impcap_darwin_dns').is(":checked") ) {
      $('#impcap-dns').show();
    } else {
      $('#impcap-dns').hide();
    }
  }
  $('#id_enable_impcap_darwin_dns').on('change', toggle_impcap_darwin);

  /* Show darwin content inspection option depending on enable checkbox */
  function toggle_impcap_pkt_inspect() {
    if( $('#id_enable_pkt_inspect').is(":checked") ) {
      $('#pkt-inspect').show();
    } else {
      $('#pkt-inspect').hide();
    }
  }
  $('#id_enable_pkt_inspect').on('change', toggle_impcap_pkt_inspect);

  var port_regex = /\bport\s+53\b/;
  var udp_regex = /\budp\b/;

  /* Show DNS options in "udp" and "port 53" is in impcap_filter */
  function toggle_impcap_filter() {
    var impcap_filter_val = $('#id_impcap_filter').val();

    if (impcap_filter_val.match(port_regex) !== null && impcap_filter_val.match(udp_regex) !== null) {
      $('.impcap-dns-mode').show();
    } else {
      $('#id_enable_impcap_darwin_dns').prop("checked", false);
      toggle_impcap_darwin();
      $('.impcap-dns-mode').hide();
    }
  }
  $('#id_impcap_filter').on('keyup', toggle_impcap_filter);


  function refresh_impcap_options() {
    toggle_impcap_filter_type();
    toggle_impcap_darwin();
    toggle_impcap_pkt_inspect();
  }


  /* Show fields depending on chosen mode */
  var last_enable_log = ($('#id_mode').val()!=="log") ? ($('#id_enable_logging').is(":checked")) : (false);
  $('#id_mode').on('change', function(event) {
    var mode = $(this).val();
    $('.http-mode').hide();
    $('.tcp-mode').hide();
    $('.log-mode').hide();
    $('.impcap-mode').hide();
    $('.'+mode+'-mode').show();

    /* If mode = LOG => Activate logging automatically */
    var log_enabled = $('#id_enable_logging').is(":checked");
    if( (mode === "log" || mode === "impcap") && !log_enabled ) {
      $('#id_enable_logging').trigger('click');
      $('#id_enable_logging').prop("disabled", true);
      last_enable_log = log_enabled;
      if( mode === "impcap" )
        refresh_impcap_options();
    } else if( mode !== "log" && mode !== "impcap" ) {
      if( mode === "http" ) {
        refresh_http();
        $('#id_enable_logging').prop("disabled", false);
        if( last_enable_log != log_enabled )
          $('#id_enable_logging').trigger('click');
      }
    } else if ( mode === "log" ) {
      last_enable_log = log_enabled;
      $('#id_enable_logging').prop("disabled", true);
      if( $('#stock_logs_locally').is(':checked') ) {
        $('#stock_logs_locally').click();
      }

      refresh_input_logs_type($('#id_listening_mode').val());
    }
    $('#id_enable_logging').trigger("change");
    refresh_ruleset($('#id_ruleset').val());

    show_custom_conf(mode, $('#id_listening_mode').val());
    show_listening_mode(mode, $('#id_listening_mode').val());
    show_network_conf(mode, $('#id_listening_mode').val());
    show_log_condition_failure();
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
  }).trigger("change");


  /* Show log_condition_failure depending on mode and ruleset */
  function show_log_condition_failure() {
    if( $('#id_mode').val() == "log" && ['raw_to_json', 'impcap'].indexOf($('#id_ruleset').val()) < 0 ) {
      $('.log-failure').show();
    } else {
      $('.log-failure').hide();
    }
  }

  /* Parser type bind */
  function refresh_ruleset(val) {
    if( val === "forwarder" ) {
      $('.forwarder-tag').show();
    } else {
      $('.forwarder-tag').hide();
    }

    if (val.startsWith("api_")){
      $('.api_clients_row').hide();
      $('.'+val+"_row").show();
    }

    show_log_condition_failure();
  }
  $('#id_ruleset').on("change", function() {
    refresh_ruleset($(this).val());
  }).trigger('change');

  /* Listening_mode bind */
  $('#id_listening_mode').on("change", function(e) {
    show_custom_conf($('#id_mode').val(), $(this).val());
    show_listening_mode($('#id_mode').val(), $(this).val());
    show_network_conf($('#id_mode').val(), $(this).val());
    refresh_input_logs_type($(this).val());
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

  /* Build request-headers and listeners fields with tables content */
  $('#frontend_edit_form').submit(function(event) {
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
        var enabled = tr.children[1].children[0].checked;
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
      var enabled = tr.children[0].children[0].value;
      var reputation_ctx = tr.children[1].children[0].value;
      var arg_field = tr.children[2].children[0].value;
      reputation_ctxs.push({'enabled': enabled, 'reputation_ctx': reputation_ctx, 'arg_field': arg_field});
    });
    $('#reputation_contexts').val(JSON.stringify(reputation_ctxs));

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

  refresh_log_forwarders($('#id_log_forwarders').val());

  /* Initialize all custom fields */
  refresh_table_events();

}); // end of function()

$(function(){
    var elems = Array.prototype.slice.call(document.querySelectorAll('.js-switch'));
    elems.forEach(function(html) {
      var switchery = new Switchery(html);
    });
})