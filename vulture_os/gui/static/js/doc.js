function bind_buttons(){
	$('#close_documentation_tab').unbind('click');
	$('#close_documentation_tab').on('click', function(){
		$('#documentation_tab').html('');
		$('#documentation_tab').css('right', '-50%');
	})
}


$(function(){

	$('#documentation').on('click', function(){
		$.get(
			documentation_uri,
			{
				path: window.location.pathname
			},

			function(response){
				if (!response.status){
					notify('error', gettext('Erreur'), response.error)
					return;
				}

				if ($('#documentation_tab').css('right') !== "0px")
					$('#documentation_tab').css('right', 0);

				$('#documentation_tab').html(response.html);

				converter = new showdown.Converter(),
                readme = converter.makeHtml(response.readme);
				
				$('#documentation_content').html(readme)
				bind_buttons();
			}
		)
	})
})