$(function(){
	$('#register_link').on('click', function(){
		$('#login_header').hide();
		$('#login_form').hide();
		$('#login_buttons').hide();

		$('#register_header').show();
		$('#register_form').show();
		$('#register_buttons').show();
	})

	$('#login_link').on('click', function(){
		$('#register_header').hide();
		$('#register_form').hide();
		$('#register_buttons').hide();
	
		$('#login_header').show();
		$('#login_form').show();
		$('#login_buttons').show();

	})
})