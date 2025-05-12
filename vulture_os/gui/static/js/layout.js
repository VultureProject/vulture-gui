
var language_datatable = {
  sLengthMenu: '_MENU_',
  oPaginate  :{
    sNext    : '',
    sPrevious: ''
  }
}

var process_queue_table;

var aoColumns_process = [
  {
    sTitle: gettext('Date add'),
    name: "date_add",
    aTargets: [0],
    defaultContent: "", 
    mData: "date_add",
    mRender: function(data, type, row){
      try{
        return moment(data).format('DD/MM/YYYY HH:mm:ss')
      } catch(err){
        return data;
      }
    }
  },
  {
    sTitle: gettext("Date update"),
    name: "modified", 
    aTargets: [1],
    defaultContent: "", 
    mData: "modified",
    mRender: function(data, type, row){
      try{
        return moment(data).format('DD/MM/YYYY HH:mm:ss')
      } catch(err){
        return data;
      }
    }
  },
  {
    sTitle: gettext("Node"),
    name: "node", 
    aTargets: [2],
    defaultContent: "", 
    mData: "node"
  },
  {
    sTitle: gettext("Action"),
    name: "action", 
    aTargets: [3],
    defaultContent: "", 
    mData: "action"
  },
  {
    sTitle: gettext("Status"),
    name: "status",
    aTargets: [4],
    defaultContent: "",
    mData: "status",
    mRender: function(data, type, row){
      if (data === "new")
        return "<i class='fas fa-plus'></i>";
      else if (data === "running")
        return "<i class='fas fa-spinner fa-spin'></i>";
      else if (data === "done")
        return "<i class='fas fa-check'></i>";
      else if (data === "failure")
        return "<i class='fas fa-exclamation-triangle'></i>";
      return "<i class='fas fa-question'></i>";
    }
  }
];

var ProcessQueueCanRedraw = true;

var columns_task_table = [];
for (var i in aoColumns_process){
  columns_task_table.push(aoColumns_process[i].mData);
}

process_queue_table = $('#table-process').dataTable({
  bServerSide    : true,
  aaSorting      : [[0, 'desc']],
  bProcessing    : false,
  bSort          : true,
  bSearchable    : false,
  bPaginate      : false,
  sScrollY       : '400px',
  sScrollCollapse: true,
  aoColumnDefs   : aoColumns_process,
  language       : language_datatable,
  sDom           : '<"top">rt<"bottom"><"clear">',
  sAjaxSource    : '/process_queue/',
  sServerMethod  : 'POST',
  fnServerData   : function(sSource, aoData, fnCallback){

    aoData.push({
      name: 'csrfmiddlewaretoken',
      value: getCookie('csrftoken')
    })

    aoData.push({
      name: 'columns',
      value: JSON.stringify(columns_task_table)
    })

    $.ajax({
      type: "POST",
      url: sSource,
      data: aoData,
      success: function(data){
        if (check_json_error(data))
          fnCallback(data);
      }
    })
  },
  fnCreatedRow: function(nRow, aData, iDataIndex){
    /* Events binding to print a frontend conf */
    $(nRow).on('click', function(e) {
      var html = "<b>" + aData['action'] + ": " + aData['result'].split('\n').join('<br/>') + "</b></br>";

      if (aData['config'])
        html += "</br><pre>" + aData['config'] + "</pre>"

      if (process_queue_table.fnIsOpen(nRow)){
        // User closed a row details
        process_queue_table.fnClose(nRow);
        ProcessQueueCanRedraw = true;
      } else {
        process_queue_table.fnOpen(nRow, html, 'details');
        // User opened a row details
        ProcessQueueCanRedraw = false;
      }

    });
  }, // fnCreatedRow: function

  fnDrawCallback: function(settings){
    ProcessQueueCanRedraw = true;
  }, // fnDrawCallback: function

});

function doRedrawDatatable() {
  processQueueResponse = false;
  process_queue_table.fnDraw();
};

setInterval(function(){
  if(ProcessQueueCanRedraw == true) {
    doRedrawDatatable();
  }
}, 5000);

$('#reload_process_queue').on('click', doRedrawDatatable);
