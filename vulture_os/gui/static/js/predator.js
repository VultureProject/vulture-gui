function init_charts(){
	var longitude = $('#shodan_longitude').val();
	var latitude = $('#shodan_latitude').val();

	if (longitude && latitude){
		$('#geomap_shodan').vectorMap({
		    map              : 'world_mill_en',
		    normalizeFunction: 'polynomial',
		    hoverOpacity     : 0.7,
		    hoverColor       : false,
		    backgroundColor  : 'transparent',
		    regionStyle      : {
		      initial      : {
		        fill            : 'rgba(210, 214, 222, 1)',
		        'fill-opacity'  : 1,
		        stroke          : 'none',
		        'stroke-width'  : 0,
		        'stroke-opacity': 1
		      },
		      selected     : {
		        fill: 'yellow'
		      },
		      selectedHover: {}
		    },
		    markerStyle      : {
		      initial: {
		        fill  : '#00a65a',
		        stroke: '#111'
		      }
		    },
		    markers          : [
		      { latLng: [parseFloat(latitude), parseFloat(longitude)], name: tag_name },
		    ]
		});
	}
}

setTimeout(function(){
	$('#tab_enrich a:first').tab('show');
}, 200);

$(function(){
	$('#close_predator_tab').on('click', function(){
		$('#predator_tab').html('');
		$('#predator_tab').css('right', '-50%');
	})
})