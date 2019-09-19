var reportrange;
var gridster;

var network;
var vis_nodes = [];
var vis_edges = [];
var interval;

var vis_tmp_nodes = new vis.DataSet();
var vis_tmp_edges = new vis.DataSet();

var search_list;
var table_loaded = false;
var show_graph = false;
var chart;
var selected_type;
var selected_app;
var predator_columns;
var filters = [];
var csrf_name = 'csrftoken';
var mapping_type = {
    'keyword': 'string',
    'text': 'string',
    'ip': 'string',
    'long': 'integer',
    'integer': 'integer'
}

var is_loading = false;

var custom_label = gettext("Customize");
var to_label = gettext("to");
var from_label = gettext("From");
var cancel_label = gettext("Cancel");
var apply_label = gettext("Apply");
var daysOfWeek = [gettext("Su"), gettext("Mo"), gettext("Tu"), gettext("We"), gettext("Th"), gettext("Fr"), gettext("Sa")];

var monthNames = [gettext("January"), gettext("February"), gettext("March"), gettext("April"), gettext("May"), gettext("June"), gettext("July"), gettext("August"), gettext("September"), gettext("October"), gettext("November"), gettext("December")];


$(function(){
    reportrange = $('#reportrange_logs').daterangepicker({
        format             : 'MM/DD/YYYY HH:mm:ss',
        minDate            : '01/01/1970',
        showDropdowns      : true,
        showWeekNumbers    : true,
        timePicker         : true,
        timePickerIncrement: 1,
        timePicker24Hour   : true,
        ranges             : ranges,
        opens              : 'right',
        buttonClasses      : ['btn', 'btn-sm'],
        applyClass         : 'btn-primary',
        cancelClass        : 'btn-default',
        separator          : ' to ',
        locale: {
            applyLabel      : apply_label,
            cancelLabel     : cancel_label,
            fromLabel       : from_label,
            toLabel         : to_label,
            customRangeLabel: custom_label,
            daysOfWeek      : daysOfWeek,
            monthNames      : monthNames,
            firstDay        : 1,
        },
        dateLimit: {
            days: 30
        }
    }, function(start, end, label) {
        start_time = start.valueOf();
        end_time   = end.valueOf();

        if (label === custom_label)
            label = start.format("DD/MM/YYYY HH:mm") + " <i class='fa fa-arrow-right'></i> " + end.format("DD/MM/YYYY HH:mm")

        $('#reportrange_logs').html(label);

        reinit_vis()

        sessionStorage.setItem('startDate', start.format());
        sessionStorage.setItem('endDate', end.format());
        sessionStorage.setItem('label', label);

        scroll_id = null;

        fetch_data()
    });

    var start = sessionStorage.getItem('startDate');
    var end = sessionStorage.getItem('endDate');
    var label = sessionStorage.getItem('label');

    if (start && end && label){
       $('#reportrange_logs').html(label);
       $('#reportrange_logs').data('daterangepicker').setStartDate(moment(start));
       $('#reportrange_logs').data('daterangepicker').setEndDate(moment(end));
    } else {
       $('#reportrange_logs').html(gettext('Today'));
    }

    $('#real_time').on('click', function(){
        // Hide or show reportrange/pagination controls and ajax loader information
        if ($(this).data('active')){
            $(this).removeClass('btn-warning').addClass('btn-default');
            $('#spinner_ajax').removeClass('fa-pulse');
            $('#reportrange_logs').prop('disabled', false);
            $(this).data('active', false);

            var tmp_startDate = sessionStorage.getItem('startDate');
            var tmp_endDate = sessionStorage.getItem('endDate');
            var tmp_label = sessionStorage.getItem('label');
            $('#reportrange_logs').data('daterangepicker').setStartDate(moment(tmp_startDate));
            $('#reportrange_logs').data('daterangepicker').setEndDate(moment(tmp_endDate));
            $('#reportrange_logs').html(tmp_label);

            reinit_vis()

            fetch_data()
        } else {
            $(this).removeClass('btn-default').addClass('btn-warning');
            $('#spinner_ajax').addClass('fa-pulse');

            var startDate = $('#reportrange_logs').data('daterangepicker').startDate;
            var endDate = $('#reportrange_logs').data('daterangepicker').endDate;

            sessionStorage.setItem('startDate', startDate);
            sessionStorage.setItem('endDate', endDate);
            sessionStorage.setItem('label', $('#reportrange_logs').html());

            $('#reportrange_logs').html(gettext('Last 5 minutes'));
            $('#reportrange_logs').prop('disabled', true);
            $(this).data('active', true);
            scroll_id = null;

            reinit_vis();
            fetch_data()
        }
    });

    $('#btn-graph').on('click', function(){
        var pressed = $(this).attr('aria-pressed');
        if (pressed === "false"){
            show_graph = true;

            $('#traffic').css('height', "800px");

            $(this).removeClass('btn-default').addClass('btn-warning');
            $('#btn-reset').hide();
            $('#btn-export').hide();
            $('#btn-configuration').hide();

            $('#graph_logs_div').hide();
            $('#table_logs_div').hide();

            setTimeout(function(){
                init_vis();
            }, 100);

        } else {
            show_graph = false;

            reinit_vis(true);

            $('#graph_logs_div').show();
            $('#table_logs_div').show();

            $('#traffic').css('height', "0px");
            $(this).removeClass('btn-warning').addClass('btn-default');
            $('#btn-reset').show();
            $('#btn-export').show();
            $('#btn-configuration').show();
        }

        fetch_data();
    })

    $('.btn-open').on('click', function(){
        var state = $(this).data('state');
        var row = $(this).data('row');

        if (state === 'close'){
            $('#'+row).slideDown(500);
            $(this).data('state', 'open');

        } else if (state === 'open'){
            $('#'+row).slideUp(500);
            $(this).data('state', 'close');
        }
    })

    $('.btn-close').on('click', function(){
        var row = $(this).data('row');
        $("#"+row).slideUp(500);
    })

    $('.resize-font').on('click', function(){
        var type = $(this).data('type');
        var size = parseInt($('#table_logs tbody td').css('fontSize'));

        switch (type) {
            case 'smaller':
                var font = size - 1 + "px";
                $('#table_logs tbody td').css({'fontSize': font});
                break;

            case 'bigger':
                var font = size + 1 + "px";
                $('#table_logs tbody td').css({'fontSize': font});
                break;

            case 'origin':
                $('#table_logs tbody td').css({'fontSize': "10px"});
                break;
        }
    })

    $('#btn-execute').unbind('click');
    $('#btn-execute').on('click', function(){
        fetch_data()
    })

    $('#btn-reset').unbind('click');
    $('#btn-reset').on('click', function(){
        $('#queryBuilder').queryBuilder('reset');
        fetch_data()
        $('#edit_search').hide();
    })

    $('#add_field').on('click', function(){
        var value = $("#selected-fields").val();

        var el = $.parseHTML(`<div class="grid-stack-item"><a href="#" data-grid='${value}' class='delete_grid'><i class='fa fa-times'></i></a><div class="grid-stack-item-content">${value}</div></div>`);
        var grid = $('.grid-stack').data('gridstack');
        var nodes = grid.grid.nodes;

        var l = 0;
        for (var i in nodes){
            if (nodes[i].id === value)
                return false;

            l += nodes[i].width;
        }

        if (l === 12){
            notify('error', max_column, '');
            return false;
        }

        grid.addWidget(el, 1, 1, 1, 1, true, 1, 3, 1, 1, value);

        $('.delete_grid').unbind('click');
        $('.delete_grid').on('click', delete_grid);
    })

    $('.resize-font').on('click', function(){
        var type = $(this).data('type');
        var size = parseInt($('#table_logs tbody td').css('fontSize'));

        switch (type) {
            case 'smaller':
                var font = size - 1 + "px";
                $('#table_logs tbody td').css({'fontSize': font});
                break;

            case 'bigger':
                var font = size + 1 + "px";
                $('#table_logs tbody td').css({'fontSize': font});
                break;

            case 'origin':
                $('#table_logs tbody td').css({'fontSize': "10px"});
                break;
        }
    })

    $("body").on('click', function(){
        $('#table_logs tbody tr').removeClass('selected');
    })

    $('#save_search').on('click', function(){
        save_search();
    })

    $('#edit_search').on('click', function(){
        save_search($(this).data('pk'));
    })

    $('#saved-search').on('change', function(){
        if ($(this).val() === ""){
            $('#edit_search').hide();
            return false;
        }

        var value = $(this).val().split('|');

        var pk = value[0];

        var rules = JSON.parse(value[1]);
        $('#queryBuilder').queryBuilder('setRules', rules);
        $('#delete_search').show();

        $('#edit_search').data('pk', pk);
        $('#search_name').val($("#saved-search option:selected").text());
        $('#edit_search').show();
    })

    $('#save_config').on('click', function(){
        var grid = $('.grid-stack').data('gridstack');
        var tmp_nodes = grid.grid.nodes;
        var nodes = {};

        var size = parseInt($('#table_logs tbody td').css('fontSize'));
        var length = $('#lengthtable').val();

        if (length > 200){
            $('#lengthtable').val(200);
            length = 200;
        }

        for (var i in tmp_nodes){
            nodes[tmp_nodes[i].x] = {
                name: tmp_nodes[i].id,
                width: tmp_nodes[i].width,
                x: tmp_nodes[i].x
            }
        }

        $.post(
            '',
            {
                action: "save_config",
                table_config: JSON.stringify(nodes),
                type_logs: selected_type,
                size: size,
                length: length,
            },

            function(response){
                if (check_json_error(response)){
                    $('button[data-row="row-configuration"]').click();
                    notify('success', gettext('Success'), gettext('Configuration saved'));

                    data = {
                        mapping: mapping,
                        config: {
                            displayed_columns: nodes,
                            font_size: size,
                            nb_lines: length
                        },
                    }

                    init_datatable(data);
                    init_configuration(data);
                    init_search(data);
                }
            }
        )
    })

    $('#delete_search').on('click', function(){
        // Delete the selected search
        var search_val = $('#saved-search').val();
        if (search_val === "")
            return false;

        var pk = $('#saved-search option:selected').val().split('|')[0];

        $.post(
            '',
            {
                action: "delete_search",
                pk: pk
            },

            function(response){
                if (check_json_error(response)){
                    notify('success', gettext('Success'), gettext('Search deleted'));
                    $('#saved-search option:selected').remove();
                }
            }

        )
    })
})

function fetch_data(){
    if (!is_loading){
        $('#table_logs').dataTable().fnDraw();
        if (show_graph)
            init_graph();
    }
}

function reinit_vis(noinit){
    if (network)
        network.destroy();

    vis_nodes = [];
    vis_edges = [];

    vis_tmp_nodes = new vis.DataSet();
    vis_tmp_edges = new vis.DataSet();

    if (!noinit)
        init_vis();
}

function init_vis(){
    var container = document.getElementById('traffic');

    var data = {
        nodes: vis_tmp_nodes,
        edges: vis_tmp_edges
    }

    var options = {
        nodes: {
            shape: 'dot',
            size: 20,
            font: {
                size: 15,
                color: '#fff'
            },
            borderWidth: 2
        },
        edges: {
            width: 2
        },
        groups: {
            diamonds: {
                size: 2,
                label: '',
                color: {background:'red',border:'white'},
                shape: 'diamond'
            },
            dotsWithLabel: {
                label: "I'm a dot!",
                shape: 'dot',
                color: 'cyan'
            },
            mints: {color:'rgb(0,255,140)', size: 10},
            icons: {
                shape: 'icon',
                icon: {
                    face: 'FontAwesome',
                    code: '\uf0c0',
                    size: 50,
                    color: 'orange'
                }
            }
        }
    };

    network = new vis.Network(container, data, options);
}

function init_graph(){
    try{
        var rules = $('#queryBuilder').queryBuilder('getMongo');
    } catch(err){
        var rules = {}
    }

    var startDate = reportrange.data('daterangepicker').startDate;
    var endDate = reportrange.data('daterangepicker').endDate;

    if ($('#real_time').data('active')){
        startDate = moment().subtract(5, 'minutes');
        endDate = moment();
    }

    startDate = startDate.format("YYYY-MM-DDTHH:mm:ssZZ")
    endDate = endDate.format("YYYY-MM-DDTHH:mm:ssZZ")

    var data = {
        'type_logs': selected_type,
        'frontend_name': selected_app,
        'startDate': startDate.format(),
        'endDate': endDate.format(),
        'rules': JSON.stringify(rules)
    }

    $.post(
        'graph',
        data,

        function(response){
            var data = response.data;

            for (var tmp of data){
                if ($.inArray(tmp.src_ip, vis_nodes) === -1){
                    vis_nodes.push(tmp.src_ip);

                    vis_tmp_nodes.add([{
                        id: tmp.src_ip,
                        label: tmp.src_ip,
                        group: "mints"
                    }])
                }

                if ($.inArray(tmp.dst_ip, vis_nodes) === -1){
                    vis_nodes.push(tmp.dst_ip);

                    vis_tmp_nodes.add([{
                        id: tmp.dst_ip,
                        label: tmp.dst_ip,
                        group: "mints"
                    }])
                }

                var src_dst = `${tmp.src_ip}-${tmp.dst_ip}`;
                var dst_src = `${tmp.dst_ip}-${tmp.src_ip}`;


                if ($.inArray(src_dst, vis_edges) === -1){
                    if ($.inArray(dst_src, vis_edges) === -1){
                        vis_edges.push(src_dst);
                        vis_edges.push(dst_src);

                        vis_tmp_edges.add({
                            from: tmp.src_ip,
                            to: tmp.dst_ip,
                            length: 10,
                            label: tmp.count
                        })
                    }
                }
            }

            network.redraw();
        }
    )
}

function packet_filter_context_menu_callback(type, log_line){
    $.post(
        system_pf_list_uri,
        {
            action: 'add',
            list_type: type,
            ip_address: log_line
        },

        function(response){
            if (!response.status){
                notify('danger', gettext('Error'), response.error);
            } else {
                notify('success', gettext('Success'));
            }
        }
    )
}

function waf_context_menu_callback(type, log_line){
    var uri = access_rule_uri + "?log_id="+log_line._id;
    window.open(uri, "_blank");
}

function rules_preview(){
    // Show preview of queryBuilder rules. SQL Syntax
    var rules_sql = $('#queryBuilder').queryBuilder('getSQL', false);
    if (rules_sql)
        $('#logs_preview_rule').val(rules_sql.sql);
    else
        $('#logs_preview_rule').val('');
}

function event_querybuilder(){
    // Refresh SQL at every change on queryBuilder
    // Event 'rulesChanged' doesn't work
    $('#queryBuilder').on('afterAddGroup.queryBuilder afterUpdateGroupCondition.queryBuilder afterDeleteGroup.queryBuilder afterAddRule.queryBuilder afterUpdateRuleFilter.queryBuilder afterUpdateRuleOperator.queryBuilder afterUpdateRuleValue.queryBuilder afterDeleteRule.queryBuilder afterReset.queryBuilder afterSetRules.queryBuilder', function(){
        scroll_id = null;
        rules_preview();
    })
}

function save_search(update){
    PNotify.removeAll();

    var search_name = $('#search_name').val();
    var rules = $('#queryBuilder').queryBuilder('getRules');

    if (rules === null)
        return false;

    if (search_name === ""){
        notify('error', erreur, name_obl);
        return false;
    }

    $.post(
        '',
        {
            action: 'save_search',
            type_logs: selected_type,
            search_name: search_name,
            update: update,
            rules: JSON.stringify(rules)
        },

        function(response){
            if (check_json_error(response)){
                notify('success', gettext('Success'), gettext("Search saved"));

                $('#search_name').val("");

                $('#saved-search').empty();
                $('#saved-search').append("<option value=''>----</option>")
                for (var i in response.searches){
                    var tmp = response.searches[i];
                    $('#saved-search').append("<option value='{0}|{1}'>{2}</option>".format(tmp.pk, JSON.stringify(tmp.search), tmp.name));
                }

                $('#saved-search').trigger('change');
            }
        }
    )
}

function delete_grid(e){
    e.stopPropagation();
    var value = $(this).data('grid');

    var grid = $('.grid-stack').data('gridstack');
    var nodes = grid.grid.nodes;

    for (var i in nodes){
        if (nodes[i].id === value){
            grid.removeWidget(nodes[i].el);
            break;
        }
    }
}

function render_col(col){
    var render = function(data, type, row){
        if (data === null)
            return "";
        else if (data instanceof Object)
            return JSON.stringify(data);

        return data;
    }

    if ($.inArray(col, ['time', '@timestamp', 'timestamp_app', 'timestamp', 'unix_timestamp', 'date_time']) > -1){
        render = function(data, type, row){
            try{
                var date = moment(data);
                return date.format("DD/MM/YYYY HH:mm:ss")
            } catch(err){
                return data;
            }
        }
    } else if (col === "log_level"){
        render = function(data, type, row){
            var log_level = {
                "DEBUG": "<label class='label label-default'>DEBUG</span>",
                "INFO": "<label class='label label-info'>INFO</span>",
                "WARNING": "<label class='label label-warning'>WARNING</span>",
                "ERROR": "<label class='label label-danger'>ERROR</span>",
                "CRITICAL": "<label class='label label-danger'>ERROR</span>",
            }

            return log_level[data];
        }
    } else if ($.inArray(col, predator_columns) > -1){
        render = function(data, type, row){
            var html = "";
            if (col === "src_ip" && row.country)
                html += "<img src='/static/img/flags/" + row.country.toLowerCase() + ".png' class='img-country'/>&nbsp;&nbsp"
            html += data;
            return `<a href='#' class='predator_info' data-column='${col}' data-info='${data}'>${html}</a>`
        }
    } else if ($.inArray(col, ['dns_queries']) > -1){
        render = function(data, type, row){
            result = "<ul>";
            $.each(data, function(no, dns_query){
                result += "<li>QName : " + dns_query.qname + ",\t DGA Anomaly : " + dns_query.darwin_decision + "%</li>";
            });
            return result + "</ul>";
        }
    } else if (col === "country"){
        render = function(data, type, row){
            if (data)
                return "<img src='/static/img/flags/" + data.toLowerCase() + ".png' class='img-country'/>&nbsp;&nbsp" + data;
            return "<i class='fa fa-ban'></i>";
        }
    } else if (col === "tags"){
        render = function(data, type, row){
            if (data)
                return "<label class='label label-danger'>" + data + "</label>";
            return "";
        }
    }


    return render
}

function destroy_table(){
    if (table_loaded){
        try{
            $('#table_logs').dataTable().fnDestroy()
            $('#table_logs').empty();
        } catch(err){}
    }
}

function init_configuration(data){

    mapping = data.mapping;
    config = data.config;

    $('#lengthtable').val(config.nb_lines);

    var options = {
        height: 1,
        cellHeight: 40,
        animate: true,
        width: 12,
        verticalMargin: 10,
        removable: true
    };

    $('.grid-stack').gridstack(options);
    var grid = $('.grid-stack').data('gridstack');
    grid.removeAll();

    $('#selected-fields').empty();

    $.each(mapping, function(field, type){
        $('#selected-fields').append(`<option value='${field}'>${field}</option>`);
    })

    for (var i in config.displayed_columns){
        var field = config.displayed_columns[i];
        var html = `<div class="grid-stack-item"><a href="#" data-grid='${field.name}' class='delete_grid'><i class='fa fa-times'></i></a><div class="grid-stack-item-content">${field.name}</div></div>`;
        grid.addWidget(html, field.x, 1, field.width, 1, false, 1, 4, 1, 1, field.name);
    }

    $('.delete_grid').on('click', delete_grid);
}

function init_detail_info(mapping){
    $('.detail_info').unbind('click');

    $('.detail_info').on('click', function(){
        var rules = $('#queryBuilder').queryBuilder('getRules');
        var rule  = null;

        var key   = $(this).text().split(':  ')[0];
        var value = $(this).text().split(':  ')[1];
        var type = mapping[key];

        if (type === 'integer')
            value = parseInt(value);
        else if (type === 'double')
            value = parseFloat(value);

        var tmp_rule = {
            id: key,
            field: key,
            operator: "equal",
            value: value
        }

        if (type === "dict")
            return false;

        if (type === "double")
            tmp_rule.input = "number"

        if (selected_type === "pf" && key == "hostname"){
            tmp_rule.input = "select";
            tmp_rule.values = nodes;
        }

        rule = {
            condition: 'AND',
            rules: [tmp_rule]
        }

        if (jQuery.isEmptyObject(rules))
            rules = rule;
        else
            rules['rules'].push(rule)

        $('#queryBuilder').queryBuilder('setRules', rules);
        rules_preview();
    });
}

function init_timeline(data){
    if (chart)
        chart.clear();

    var x = [];
    var y = [];

    $.each(data.graph_data, function(k, v){
        x.push(k);
        y.push(v);
    })

    var options = {
        toolbox: {
            show: true,
            showTitle: false,
            left: 0
        },
        grid: {
            left: '0%',
            top: '5%',
            right: '1%',
            bottom: '0%',
            containLabel: true
        },
        tooltip : {
            trigger: 'axis',
            axisPointer: {
                type: 'cross',
                label: {
                    backgroundColor: '#6a7985'
                }
            }
        },
        xAxis: {
            type: 'category',
            data: x,
            axisLabel: {
                show: true,
                interval: 'auto',
                rotate: 0,
                margin: 10
            }
        },
        yAxis: {
            type: 'value',
            axisLine: {
                show: false
            },
            axisTick: {
                show: false
            },
            axisLabel: {
                show: true,
                interval: 'auto',
                rotate: 30,
                margin: 10,
                textStyle: {
                    color: '#212529'
                }
            },

        },
        series: [{
            data: y,
            type: 'bar',
            itemStyle: {
                color: "#3A444E"
            }
        }]
    };

    chart = echarts.init(document.getElementById("graph_logs"))
    chart.setOption(options);
}

function init_datatable(data){
    destroy_table();

    mapping = data.mapping;
    config = data.config;
    predator_columns = data.predator_columns;

    var triable_columns = [];
    var columnsDefs = [];
    var i = 0;

    for (var j in config.displayed_columns){
        var field = config.displayed_columns[j];

        triable_columns.push(field.name);

        if ($.inArray(field.name, ['unix_timestamp', 'timestamp_app', 'time']) > -1)
            var human_label = gettext('Date')
        else
            var human_label = field.name.toLowerCase()

        columnsDefs.push({
            sTitle: human_label,
            name: field.name,
            aTargets: [i],
            mData: field.name,
            sWidth: (field.width/12) * 100 + "%",
            mRender: render_col(field.name),
            defaultContent: '-'
        })

        i++;
    }

    var settings = {
        sDom: '<pri<"top">t<"bottom"p>',
        oLanguage: {
            sLengthMenu: '_MENU_',
            oPaginate  :{
                sNext    : '',
                sPrevious: ''
            }
        },
        bAutoWidth    : true,
        bServerSide   : true,
        bfilter       : false,
        bDestroy      : true,
        aaSorting     : [[0, 'desc']],
        iDisplayLength: config.nb_lines,
        bProcessing   : true,
        bSort         : true,
        aoColumnDefs  : columnsDefs,
        sAjaxSource   : 'logs',
        sServerMethod : 'POST',
        fnServerData: function(sSource, aoData, fnCallback){
            try{
                var rules = $('#queryBuilder').queryBuilder('getMongo');
            } catch(err){
                var rules = {}
            }

            var startDate = reportrange.data('daterangepicker').startDate;
            var endDate = reportrange.data('daterangepicker').endDate;

            if ($('#real_time').data('active')){
                startDate = moment().subtract(5, 'minutes').startOf('minutes');
                endDate = moment().endOf('minutes');
            }

            startDate = startDate.format("YYYY-MM-DDTHH:mm:ssZZ")
            endDate = endDate.format("YYYY-MM-DDTHH:mm:ssZZ")

            aoData.push({
                name: 'type_logs',
                value: selected_type
            })

            aoData.push({
                name: 'frontend_name',
                value: selected_app
            })

            aoData.push({
                name: 'startDate',
                value: startDate.format()
            })

            aoData.push({
                name: 'endDate',
                value: endDate.format()
            })

            aoData.push({
                name: 'columns',
                value: JSON.stringify(triable_columns)
            })

            aoData.push({
                name: 'rules',
                value: JSON.stringify(rules)
            })

            $.ajax({
                type   : "POST",
                url    : sSource,
                data   : aoData,
                success: function(data, callback){
                    if (data.need_auth){
                        window.location.href = window.location.href;
                        return false;
                    }

                    if (!data.status){
                        notify('error', gettext('Erreur'), data.error);
                    } else {

                        init_timeline(data);

                        fnCallback(data);
                        $('#table_logs tbody td').css({'fontSize': config.font_size});
                    }
                }
            })
        },
        fnCreatedRow: function(nRow, aData, iDataIndex){
            $(aData).each(function(key, value) {
                $.each(value.dns_queries, function(key, query) {
                    if (query.darwin_decision > 80) {
                        $(nRow).css('backgroundColor', '#e75336');
                        $(nRow).css('color', '#fff');
                        $(nRow).find('a').css('color', '#fff');
                        $(nRow).find('a').removeClass('predator_info');
                        query.darwin_decision = '<span style=color:#f44336;font-weight:bold;>' + query.darwin_decision + "</span>";
                    }
                });
                if(value.darwin_is_alert) {
                    $(nRow).css('backgroundColor', '#e75336');
                    $(nRow).css('color', '#fff');
                    $(nRow).find('a').css('color', '#fff');
                    $(nRow).find('a').removeClass('predator_info');
                }
            });

            $(nRow).on('click', function(e){
                e.stopPropagation();

                $('#table_logs tbody tr').removeClass('selected');
                $(this).addClass('selected');
                $(nRow).find('td').each(function(){
                    $(this).addClass('row_selected');
                })

                var sOut = "";

                const ordered = {};
                Object.keys(aData).sort().forEach(function(key) {
                  ordered[key] = aData[key];
                });

                $.each(ordered, function(key, value){
                    if (key !== "_id"){
                        if (value instanceof Object)
                            value = JSON.stringify(value);

                        sOut += `<span class='detail_info large'><span class='key'>${key}:</span>&nbsp;&nbsp;<span class='value'>${value}</span></span>`;
                    }
                })

                if ($('#table_logs').dataTable().fnIsOpen(nRow)){
                    $('#table_logs').dataTable().fnClose(nRow);
                    $(this).removeClass('selected');

                    $(nRow).find('td').each(function(){
                        $(this).removeClass('row_selected');
                    })
                } else {
                    $('#table_logs').dataTable().fnOpen(nRow, sOut, 'details');
                    init_detail_info(mapping);
                }
            })
        }
    }

    var table = $('#table_logs').dataTable(settings).on('draw.dt', function(){
        prepare_enrich_action();

        $.contextMenu({
            selector: "#table_logs tbody tr",
            autoHide: true,

            build: function($trigger, e){
                var items = {};

                var table2 = $('#table_logs').dataTable();
                var data = table2.fnGetData($trigger[0])

                if ($.inArray(selected_type, ['pf', 'access']) !== -1){
                    items.pf_whitelist = {
                        name: gettext('PF Whitelist'),
                        callback: function(key, opt){
                            packet_filter_context_menu_callback("whitelist", data)
                        }
                    }

                    items.pf_blacklist = {
                        name: gettext('PF Blacklist'),
                        callback: function(key, opt){
                            packet_filter_context_menu_callback("blacklist", data)
                        }
                    }
                }

                if (selected_type === "access"){
                    items.waf_rule = {
                        name: gettext('WAF Rule'),
                        callback: function(key, opt){
                            waf_context_menu_callback(key, data)
                        }
                    }
                }

                return {items: items}
            }
        })
    }).on('preDraw.dt', function(e, settings, data){
        is_loading = true;
    }).on('draw.dt', function(){
        is_loading = false;
    });

    table_loaded = true;

    if (interval)
        clearInterval(interval)

    interval = setInterval(function(){
        if ($('#real_time').data('active'))
            fetch_data();
    }, 5000);
}

function fetch_mapping(type_logs, type_app){
    $.post(
        '',
        {
            type_logs: type_logs,
            action: 'get_mapping'
        },

        function(response){
            if (check_json_error(response)){
                init_configuration(response);
                init_datatable(response);
                init_search(response);
            }
        }
    )
}

function fetch_applications(type_logs){
    $('#list-applications').html('');
    // destroy_table();

    $.post(
        '',
        {
            type_logs: type_logs,
            action: 'get_available_apps'
        },

        function(response){
            if (check_json_error(response)){
                $.each(response.applications, function(pk, name){
                    $('#list-applications').append(`<li><a class='choice-applications' href="#" data-id='${pk}'>${name}</a></li>`);
                })

                $('.choice-applications').on('click', function(){
                    selected_app = $(this).data('id');
                    sessionStorage.setItem('default_app_'+type_logs, selected_app);

                    $('#btn-applications').html($(this).html());
                    fetch_mapping(selected_type, selected_app);
                })

                default_app = sessionStorage.getItem('default_app_'+type_logs);
                if (default_app)
                    $(`*[data-id="${default_app}"]`).click();
            }
        }
    )
}

function prepare_type_logs_selector(){
    $('#list-type-logs').html('');
    destroy_table();

    $.post(
        '',
        {action: 'get_available_logs'},

        function(response){
            if (check_json_error(response)){
                $.each(response.logs, function(type, text){
                    $('#list-type-logs').append(`<li><a class='choice-type-logs' href='#' data-type='${type}'>${text}</a></li>`);
                })

                $('.choice-type-logs').on('click', function(){
                    selected_app = null;
                    selected_type = $(this).data('type');
                    sessionStorage.setItem('default_type', selected_type);

                    if (selected_type === "access") {
                        $('#btn-defender').show();
                    } else {
                        $('#btn-defender').hide();
                    }

                    $('#btn-type-logs').html($(this).html());

                    if ($.inArray(selected_type, ['access', 'impcap']) > -1){
                        $('#btn-applications').show();
                        fetch_applications(selected_type);

                        default_app = sessionStorage.getItem('default_app');
                        if (default_app)
                            $(`*[data-id='${default_app}]`).click();

                    } else {
                        $('#btn-applications').hide();
                        fetch_mapping(selected_type);
                    }

                    if ($.inArray(selected_type, ['pf', 'impcap', 'access']) === -1)
                        $('#btn-graph').hide();
                    else
                        $('#btn-graph').show();
                })

                default_type = sessionStorage.getItem('default_type');
                if (!default_type)
                    default_type = 'internal';

                if (default_type)
                    $(`*[data-type='${default_type}']`).click();
            }
        }
    )
}

function init_search(data){
    mapping = data.mapping;
    config = data.config;
    search_list = data.searches;
    nodes = data.nodes;

    filters = [];

    $('#saved-search').empty();
    $('#saved-search').append("<option value=''>----</option>")
    for (var i in search_list){
        var tmp = search_list[i];
        $('#saved-search').append("<option value='{0}|{1}'>{2}</option>".format(tmp.pk, JSON.stringify(tmp.search), tmp.name))
    }

    $.each(mapping, function(field, type){
        if (type !== "dict"){
            if (type === "float")
                type = "double";
            else if (type === "number")
                type = "integer";

            var filter = {
                id: field,
                label: field,
                type: type,
                size: 60
            }

            if (type === "double" || type === "integer")
                filter.input = "number"

            if (selected_type === "pf" && field == "hostname"){
                filter.input = "select";
                filter.values = nodes;
            }

            filters.push(filter)
        }
    })

    try{
        $('#queryBuilder').queryBuilder('destroy');
    } catch(err){
    }

    builder = $('#queryBuilder').queryBuilder({
        sort_filters: true,
        allow_empty: true,
        filters: filters,
        plugins: [
            'invert',
            // 'sortable',
            'not-group'
        ]
    })

    event_querybuilder();
    rules_preview();
}

prepare_type_logs_selector();
$('.btn-open').click();