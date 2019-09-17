
$(function(){

    var option_map = {
      backgroundColor: 'transparent',
      color: ['gold','aqua','lime'],
      tooltip : {
        trigger: 'item',
        formatter: '{b}'
      },
      dataRange: {
        show: false,
        min : 0,
        max : 100,
        calculable : true,
        color: ['#EA6337', '#EA6337', '#EA6337'],
        textStyle:{
          color:'#000'
        }
      },
      series: [{
        name: 'Vulture',
        type: 'map',
        roam: false,
        hoverable: true,
        mapType: 'world',
        itemStyle:{
            normal:{
              borderColor:'#ccc',
              borderWidth:1,
              areaStyle:{
                color: '#2F373F'
              }
            }
        },
        data:[],
        geoCoord: {}
      }]
    }

    var chart_map = echarts.init(document.getElementById('map'), 'infographics');
    chart_map.setOption(option_map);

    var ips = [];

    var socket = io.connect('https://dl.vultureproject.org');
    socket.on('data', function(message) {

      if ($.inArray(message.ip, ips) > -1)
        return;

      ips.push(message.ip)

      var markline = [{
        symbol: 'circle',
        symbolSize: [2, 2],
        name: message.ip,
        geoCoord: [parseFloat(message.lon), parseFloat(message.lat)],
        label: {
          formatter: function(){
            return `IP: ${message.ip}`;
          }
        }
      }]


      chart_map.addMarkPoint(0, {
          data: markline
      })

      $('#nb_vulture').html("Output point: " + ips.length);
      $('#avg_vulture').html("Average unique instance: " + message.avg_probes);
    })

    $('#fullscreen_geomap').on('click', function(){
      if ($('#infos').hasClass('fullscreen'))
        $('#map').css('height', 900);
      else
        $('#map').css('height', 400);
      
      chart_map.resize();
    })
})