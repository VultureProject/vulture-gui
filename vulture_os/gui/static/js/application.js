function init_application_form(btn, html, app_id){
	$.post(
		'',
		{
			action: 'get_form',
			application_id: app_id
		},

		function(response){
			$(btn).html(html);
			if (response.status){
				$('#modal-application-content').html(response.template);
				$('#modal-application').modal({
					backdrop: 'static',
				    keyboard: false
				});

				var elems = Array.prototype.slice.call(document.querySelectorAll('.js-switch'));

				elems.forEach(function(elem) {
				  var switchery = new Switchery(elem);
				});

				$('.tagsinput').tagsinput();
			} else {
				notify('error', response.error);
			}
		}
	)
}

$(function(){

	var columns = [
		{title: gettext('Name'), targets: [0], data: 'name'},
		{title: gettext('Public FQDN'), targets: [1], data: 'public_fqdn'},
		{title: gettext('Public Directory'), targets: [2], data: 'public_directory'},
		{title: gettext('Private URI'), targets: [3], data: 'private_uri'},
		{title: gettext('State'), targets: [4], data: 'state', render: function(data, type, row){
			var d = {
				'RUNNING': '<label class="label label-success">' + gettext('RUNNING') + '</label>',
				'PENDING': '<label class="label label-warning">' + gettext('PENDING') + '</label>',
				'REMOVING': '<label class="label label-danger">' + gettext('REMOVING') + '</label>',
			}

			return d[data];
		}},
		{title: gettext('Actions'), targets: [5], data: '_id', orderable: false, render: function(data, type, row){
			var btns = [];

			if (row.state === 'RUNNING'){
				btns.push("<button class='btn btn-danger btn-xs btn-flat btn-stop'><i class='fa fa-stop'></i></button>&nbsp;&nbsp;");
			}

			if ($.inArray(row.state, ['RUNNING', 'PENDING']) > -1){
				btns.push("<button class='btn btn-primary btn-xs btn-flat btn-edit'><i class='fa fa-edit'></i></button>");
				btns.push("<button class='btn btn-danger btn-xs btn-flat btn-del'><i class='fa fa-trash'></i></button>");
			}

			if (row.state === "REMOVING"){
				btns.push("<button class='btn btn-warning btn-xs btn-flat btn-cancel-removal'><i class='fa fa-ban'></i></button>")
			}

			return btns.join('&nbsp;')
		}}
	]

	$('#application_table').dataTable({
	    columnDefs: columns,
	    responsive: true,
	    serverSide: true,
	    processing: true,
	    language: {
	        paginate: {
	          previous: '<i class="demo-psi-arrow-left"></i>',
	          next: '<i class="demo-psi-arrow-right"></i>'
	        }
	    },
	    ajax: {
	    	url: '',
	    	type: 'POST',
	    	data: function(d){
	    		d.action = 'get_data';
	    		d.columns = JSON.stringify(['name', 'public_fqdn', 'public_directory', 'private_uri', 'state']);
	    	}
	    },
	    createdRow: function(row, data, dataIndex){
	    	$(row).find('.btn-edit').on('click', function(){
	    		var app_id = data._id;
	    		var html = $(this).html();
				$(this).html('<i class="fa fa-spinner fa-spin"></i>');

	    		init_application_form(this, html, app_id);
	    	})

	    	$(row).find('.btn-del').on('click', function(){
	    		var app_id = data._id;

	    		var btn = this;
	    		var html = $(btn).html();
	    		$(btn).html('<i class="fa fa-spinner fa-spin"></i>');

	    		$.post(
	    			'',
	    			{
	    				action: 'del',
	    				application_id: app_id
	    			},

	    			function(response){
	    				$(btn).html(html)
	    				
	    				if (response.status){
	    					notify('success', gettext('This application will be removed'));
	    					$('#application_table').DataTable().draw();
	    				}
	    			}
	    		)
	    	})

	    	$(row).find('.btn-cancel-removal').on('click', function(){
	    		var app_id = data._id;

	    		var btn = this;
	    		var html = $(btn).html();
	    		$(btn).html('<i class="fa fa-spinner fa-spin"></i>');

	    		$.post(
	    			'',
	    			{
	    				action: 'cancel_del',
	    				application_id: app_id
	    			},

	    			function(response){
	    				$(btn).html(html)
	    				
	    				if (response.status){
	    					notify('success', gettext('This application will not be removed'));
	    					$('#application_table').DataTable().draw();
	    				}
	    			}
	    		)
	    	})
	    }
	});

	$('#application_add').on('click', function(event){
		// Change button for spinner
		var html = $(this).html();
		$(this).html('<i class="fa fa-spinner fa-spin"></i>');

		init_application_form(this, html);
	})


	$('#form_application').on('submit', function(event){
		event.preventDefault();

		var data = $(this).serializeArray();
		data.push({
			name: 'action',
			value: 'save_form'
		})

		$.post(
			'',
			data,

			function(response){
				if (!response.status){
					$('#modal-application-content').html(response.template);
				} else {
					$('#modal-application').modal('hide');
					notify('success', gettext('Application successfully saved'))
					$('#application_table').DataTable().draw();
				}
			}
		)
		
	})

	$('#modal-application').on('hidden.bs.modal', function () {
		// Empty content at modal close
		$('#modal-application-content').html('');
	})
})
