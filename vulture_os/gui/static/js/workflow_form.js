var forbidden_html = {
    "http": gettext('403 Forbidden'),
    "tcp": gettext('Deny')
}

var cors_methods = {
    '*': 'All',
    'GET': 'GET',
    'POST': 'POST',
    'PUT': 'PUT',
    'PATCH': 'PATCH',
    'DELETE': 'DELETE',
    'HEAD': 'HEAD',
    'CONNECT': 'CONNECT',
    'OPTIONS': 'OPTIONS',
    'TRACE': 'TRACE'
}

function form_backend(backend_choices, backend_id){
    var form = `<form action="" class="backend-edit">
        <div class="row">
            <div class="col-md-12 form-group">
                <label>${gettext('Applications')}</label>
                <select class="form-control backend">`;

    var backends = {}
    for (var i in backend_choices)
        backends[backend_choices[i].id] = backend_choices[i].name

    $.each(backends, function(key, val){
        var selected = "";
        if (parseInt(key) === backend_id)
            selected = "selected='selected'";

        form += `<option ${selected} value='${key}'>${val}</option>`
    })

    form += "</select></div></div></div></form>";
    return form;
}

function form_frontend(edit, cors_policy, frontend_choices, frontend_id, workflow_mode, fqdn, public_dir){
    if (!fqdn)
        fqdn = "";

    if (!public_dir)
        public_dir = "/";

    if (!cors_policy){
        cors_policy = {
            "enable_cors_policy": false,
            "allowed_methods": "*",
            "allowed_origins": "*",
            "allowed_headers": "*",
            "max_age": 600
        }
    }

    let form = '<form action="" class="frontend-edit">';

    if (edit){
        form += `<label class="col-sm-4">${gettext('Frontend')}</label>
                <div class="col-sm-7 form-group">
                    <select class="form-control frontend">`

        for (let i in frontend_choices){
            let frontend = frontend_choices[i];
            form += `<option ${parseInt(frontend.id) === parseInt(frontend_id) ? "selected='selected'" : ""} value='${frontend.id}'>${frontend.name}</option>`
        }
        form += "</select></div>"
    }

    if (!edit | workflow_mode === "http"){
        form += `<label class="col-sm-4">${gettext('FQDN')}</label>
                <div class="col-sm-7 form-group">
                    <input type="text" class="form-control fqdn" value="${fqdn}"/>
                </div>
                <label class="col-sm-4">${gettext('Public Directory')}</label>
                <div class="col-sm-7 form-group">
                    <input type="text" class="form-control public_dir" value="${public_dir}"/>
                </div>

                <label class="col-sm-4">${gettext('Enable CORS policy')}</label>
                <div class="col-sm-7 form-group">
                    <input type="checkbox" class="form-control js-switch" ${cors_policy.enable_cors_policy ? "checked" : ""} id="id_enable_cors_policy">
                </div>
                <div class="cors_options">
                <label class="col-sm-4">${gettext('Allowed methods')}</label>
                <div class="col-sm-7 form-group">
                    <select class="form-control select2" id="id_allowed_methods" multiple>`

        for (let key in cors_methods){
            form += `<option value='${key}' ${cors_policy.allowed_methods.includes(key) ? "selected=''" : ""}>${cors_methods[key]}</option>`
        }

        form += `</select>
                    </div>
                    <label class="col-sm-4">${gettext('Allowed origins')}</label>
                    <div class="col-sm-7 form-group">
                        <input type="text" value="${cors_policy.allowed_origins}" class="form-control" id="id_allowed_origins">
                    </div>
                    <label class="col-sm-4">${gettext('Allowed headers')}</label>
                    <div class="col-sm-7 form-group">
                        <input type="text" value="${cors_policy.allowed_headers}" class="form-control" id="id_allowed_headers">
                    </div>
                    <label class="col-sm-4">${gettext('Max age')}</label>
                    <div class="col-sm-7 form-group">
                        <input type="number" value="${cors_policy.max_age}" class="form-control" min="0" id="id_max_age">
                    </div>
                    </div>
                    <script>
                    $('#id_enable_cors_policy').on('change', function(event) {
                        if ($(this).is(':checked')) {
                            $('.cors_options').show();
                          } else {
                            $('.cors_options').hide();
                          }
                    });
                    $('#id_enable_cors_policy').trigger('change');
                    </script>`
    }

    form += "</form>";
    return form;
}


function form_acl(mode, edit, acls_list, acl_id, action_satisfy, redirect_url_satisfy, action_not_satisfy, redirect_url_not_satisfy){
    if (!redirect_url_satisfy)
        redirect_url_satisfy = "";

    if (!redirect_url_not_satisfy)
        redirect_url_not_satisfy = "";

    var form = "<form action='' class='acl-define-actions'>";

    if (edit){
        form += `<div class="row">
        <div class="col-md-12 form-group">
            <label>${gettext('Access Control')}</label>
            <select class='form-control access_control'>`;

        for (var i in acls_list){
            var acl = acls_list[i];
            form += `<option value="${acl.id}">${acl.name}</option>`;
        }

        form += "</select></div></div>";
    }

    if (edit)
        readonly = "readonly='readonly'";

    var selects = {
        "action_satisfy": "",
        "action_not_satisfy": ""
    }

    var actions_type = ['action_satisfy', 'action_not_satisfy'];
    for (var i in actions_type){
        var action = actions_type[i];

        var select = `<select class="form-control select2 ${action}">
            <option value="200">${gettext('Continue')}</option>
            <option value="403">${forbidden_html[mode]}</option>`

        if (mode === "http"){
            select += `
                <option value="302">${gettext('302 Redirect')}</option>
                <option value="301">${gettext('301 Permanent Redirect')}</option>
            `;
        }

        select += "</select>";
        selects[action] = select;
    }

    form += `<table class="table">
            <tbody>
                <tr>
                    <td>${gettext('If ACL satisfy then')}</td>
                    <td>${selects['action_satisfy']}</td>
                    <td class="redirect_to_line_satisfy">${gettext('Redirect to')}</td>
                    <td class="redirect_to_line_satisfy">
                        <input type="text" class="form-control redirect_url_satisfy" value="${redirect_url_satisfy}"/>
                    </td>
                </tr>
                <tr>
                    <td>${gettext("If ACL doesn't satisfy then")}</td>
                    <td>${selects['action_not_satisfy']}</td>
                    <td class="redirect_to_line_not_satisfy">${gettext('Redirect to')}</td>
                    <td class="redirect_to_line_not_satisfy">
                        <input type="text" class="form-control redirect_url_not_satisfy" value="${redirect_url_not_satisfy}"/>
                    </td>
                </tr>
            </tbody>
        </table>
    </form>
    <script>
        $('.action_satisfy').on('change', function(){
            var value = $(this).val();
            if ($.inArray(value, ["301", "302"]) > -1){
                $(".redirect_to_line_satisfy").show();
            } else {
                $('.redirect_to_line_satisfy').hide();
                $('.redirect_url_satisfy').val('');
            }
        })

        $('.action_not_satisfy').on('change', function(){
            var value = $(this).val();
            if ($.inArray(value, ["301", "302"]) > -1){
                $(".redirect_to_line_not_satisfy").show();
            } else {
                $('.redirect_to_line_not_satisfy').hide();
                $('.redirect_url_not_satisfy').val('');
            }
        })

        setTimeout(function(){
            $('.action_satisfy').trigger('change');
            $('.action_not_satisfy').trigger('change');
        }, 100)
    `

    if (acl_id){
        form += `$('.access_control').val('${acl_id}');`;
        form += `$('.action_satisfy').val('${action_satisfy}');`;
        form += `$('.action_not_satisfy').val('${action_not_satisfy}');`;
    }
    form += "</script>";

    return form;
}

function form_authentication(authentication_choices, authentication_id){
    var form = `<form action="" class="authentication-edit">
        <div class="row">
            <div class="col-md-12 form-group">
                <label>${gettext('Authentication Portal')}</label>
                <select class="form-control authentication">`;

    var authentication_choice = {}
    for (var i in authentication_choices)
        authentication_choice[authentication_choices[i].id] = authentication_choices[i].name

    $.each(authentication_choice, function(key, val){
        var selected = "";
        if (parseInt(key) === authentication_id)
            selected = "selected='selected'";

        form += `<option ${selected} value='${key}'>${val}</option>`
    })
    form += "</select></div></div></div></form>";

    return form;
}

function form_authentication_filter(authentication_filter_choices, authentication_filter_id){
    form = `<form action="" class="authentication_filter-edit">
    <div class="row">
    <div class="col-md-12 form-group">
    <label>${gettext('Authentication Scope Filter')}</label>
    <select class="form-control authentication_filter">`;

    var authentication_filter_choice = {}
    for (var i in authentication_filter_choices)
    authentication_filter_choice[authentication_filter_choices[i].id] = authentication_filter_choices[i].name

    $.each(authentication_filter_choice, function(key, val){
        var selected = "";
        if (parseInt(key) === authentication_filter_id)
        selected = "selected='selected'";

        form += `<option ${selected} value='${key}'>${val}</option>`
    })
    form += "</select></div></div></div></form>";

    return form;
}
