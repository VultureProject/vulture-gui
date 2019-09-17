var enrich_used = false;

function packet_filter_context_menu_callback(type, ip){
    $.post(
        system_pf_list_uri,
        {
            action: 'add',
            list_type: type,
            ip_address: ip
        },

        function(response){
            if (!response.status){
                notify('danger', gettext('Error'), response.error);
            } else {
                notify('success', gettext('Succes'));
            }
        }
    )
}

function enrich_informations(column, info, elem, old_column, old_info){
  var html = $(elem).html();
  $(elem).html("<i class='fa fa-spinner fa-spin'></i>&nbsp;");

  PNotify.removeAll();

  enrich_used = true;

  $.post(
    predator_uri,
    {
      column: column,
      info: info,
      old_column: old_column,
      old_info: old_info
    },

    function(response){
      enrich_used = false;
      
      $(elem).html(html);
      if (response.need_auth){
        window.location.href = window.location.href;
        return;
      }

      if (!response.status){
        notify('danger', gettext('Error'), response.error);

        if ($('#predator_tab').css('right') === "0px")
          $('#predator_tab').css('right', '-50%');

        return;
      }

      if ($('#predator_tab').css('right') !== "0px")
        $('#predator_tab').css('right', 0);

      $('#predator_tab').html(response.data);

      $("#vuln_accordion").collapse();
      prepare_enrich_action()

      setTimeout(function(){
        init_charts();
      }, 200)
    }
  )
}

function prepare_enrich_action(){
  $('.predator_info').unbind('click');

  $('.predator_info').on('click', function(e){
    e.stopPropagation();

    if (enrich_used)
      return;

    var column = $(this).data('column');
    var info = $(this).data('info');

    if ($('#tag_info_value').html()){
      var old_column = $('#tag_info_value').data('column');
      var old_info = $('#tag_info_value').data('info');

      if (info === old_info)
        return;
    }

   enrich_informations(column, info, this, old_column, old_info);
  });

  $.contextMenu({
    selector: '.predator_info',

    build: function($trigger, e){

      var value = $($trigger).html();

      var re_ipv4 = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/i;
      var re_ipv6 = /^((?=.*::)(?!.*::.+::)(::)?([\dA-F]{1,4}:(:|\b)|){5}|([\dA-F]{1,4}:){6})((([\dA-F]{1,4}((?!\3)::|:\b|$))|(?!\2\3)){2}|(((2[0-4]|1\d|[1-9])?\d|25[0-5])\.?\b){4})$/i;

      var items = {};
      if (re_ipv4.test(value) || re_ipv6.test(value)){

        items.submit = {
          name: gettext("Report IP abuse"),
          callback: function(key, opt){

            $.post(
              predator_submit_uri,
              {ip: value},

              function(response){
                if (!response.status){
                  notify('danger', gettext('Error'), response.error);
                  return false;
                } 

                notify('success', gettext('Succes'), response.message);
              }
            )
          }
        }

        items.whitelist = {
          name: gettext('PF Whitelist'),
          callback: function(key, opt){
              packet_filter_context_menu_callback(key, value)
          }
        }

        items.blacklist = {
          name: gettext('PF Blacklist'),
          callback: function(key, opt){
              packet_filter_context_menu_callback(key, value)
          }
        }
      }

      return {items: items}
    }
  })
}