function init_pki_form(btn, html, pki_id){
	$.post(
		'',
		{
			action: 'get_form',
			pki_id: pki_id
		},

		function(response){
			$(btn).html(html);
			if (response.status){
				$('#modal-pki-content').html(response.template);
				$('#modal-pki').modal({
					backdrop: 'static',
				    keyboard: false
				});

				var elems = Array.prototype.slice.call(document.querySelectorAll('.js-switch'));

				elems.forEach(function(elem) {
				  var switchery = new Switchery(elem);
				});

				$('.tagsinput').tagsinput();

				$('#id_key').unbind('change');
				$('#id_key').on('change', askpass);
				askpass();
			} else {
				notify('error', response.error);
			}
		}
	)
}

function askpass(){
	var value = $(this).val();
	console.log(value)

	$('.keypass').hide();
	if (value.match(/ENCRYPTED/))
		$('.keypass').show();
}

$(function(){

	var columns = [
		{title: gettext('Name'), targets: [0], data: 'name'},
		{title: gettext('Actions'), targets: [1], data: '_id', orderable: false, render: function(data, type, row){
			var btns = [];

			btns.push("<button class='btn btn-primary btn-xs btn-flat btn-edit'><i class='fa fa-edit'></i></button>");
			btns.push("<button class='btn btn-danger btn-xs btn-flat btn-del'><i class='fa fa-trash'></i></button>");

			return btns.join('&nbsp;')
		}}
	]

	$('#pki_table').dataTable({
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
	    		d.columns = JSON.stringify(['name']);
	    	}
	    },
	    createdRow: function(row, data, dataIndex){
	    	$(row).find('.btn-edit').on('click', function(){
	    		var pki_id = data._id;
	    		var html = $(this).html();
				$(this).html('<i class="fa fa-spinner fa-spin"></i>');

	    		init_pki_form(this, html, pki_id);
	    	})

	    	$(row).find('.btn-del').on('click', function(){
	    		var pki_id = data._id;

	    		var btn = this;
	    		var html = $(btn).html();
	    		$(btn).html('<i class="fa fa-spinner fa-spin"></i>');

	    		$.post(
	    			'',
	    			{
	    				action: 'del',
	    				pki_id: pki_id
	    			},

	    			function(response){
	    				$(btn).html(html)
	    				
	    				if (response.status){
	    					notify('success', gettext('This pki will be removed'));
	    					$('#pki_table').DataTable().draw();
	    				}
	    			}
	    		)
	    	})
	    }
	});

	$('#pki_add').on('click', function(event){
		// Change button for spinner
		var html = $(this).html();
		$(this).html('<i class="fa fa-spinner fa-spin"></i>');

		init_pki_form(this, html);
	})


	$('#form_pki').on('submit', function(event){
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
					$('#modal-pki-content').html(response.template);
				} else {
					$('#modal-pki').modal('hide');
					notify('success', gettext('pki successfully saved'))
					$('#pki_table').DataTable().draw();
				}
			}
		)
		
	})

	$('#modal-pki').on('hidden.bs.modal', function () {
		// Empty content at modal close
		$('#modal-pki-content').html('');
	})
})
