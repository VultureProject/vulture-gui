function notify(type, title, message){
	var option = {
		type: type,
		container: "floating",
		title: title,
		closeBtn: true,
		floating: {
			position: 'top-center'
		},
	}

	if (type === "success"){
		option.icon = "fa fa-check";
		option.timer = 5000;

	} else if (type === "error"){
		option.icon = "fa fa-times";
		option.timer = 0;
	}

	if (message)
		option.message = message;

	$.niftyNoty(option);
}