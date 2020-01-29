var forbidden_html = {
    "http": gettext('403 Forbidden'),
    "tcp": gettext('Deny')
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

function form_frontend(edit, frontend_choices, frontend_id, workflow_mode, fqdn, public_dir){
    if (!fqdn)
        fqdn = "";

    if (!public_dir)
        public_dir = "/";

    var form = '<form action="" class="frontend-edit">';

    if (edit){
        var form = `<form action="" class="frontend-edit">
            <div class="row">
                <div class="form-group col-md-12">
                    <label>${gettext('Frontend')}</label>
                    <select class="form-control frontend">`

        var frontends = {}
        for (var i in frontend_choices){
            var frontend = frontend_choices[i];
            if (frontend.mode === workflow_mode)
                frontends[frontend.id] = frontend.name
        }

        $.each(frontends, function(key, val){
            var selected = "";
            if (parseInt(key) === parseInt(frontend_id))
                selected = "selected='selected'";

            form += `<option ${selected} value='${key}'>${val}</option>`
        })

        form += "</select></div>"

        if (workflow_mode === "http"){
            form += `<div class="form-group col-md-12">
                        <label>${gettext('FQDN')}</label>
                        <input type="text" class="form-control fqdn" value="${fqdn}"/>
                    </div>
                    <div class="form-group col-md-12">
                        <label>${gettext('Public Directory')}</label>
                        <input type="text" class="form-control public_dir" value="${public_dir}"/>
                    </div>`
        }
    } else {
        form += `<div class="form-group col-md-12">
                    <label>${gettext('FQDN')}</label>
                    <input type="text" class="form-control fqdn" value="${fqdn}"/>
                </div>
                <div class="form-group col-md-12">
                    <label>${gettext('Public Directory')}</label>
                    <input type="text" class="form-control public_dir" value="${public_dir}"/>
                </div>`;
    }

    form += "</div></form>";
    return form;
}

function form_waf(waf_list, waf_id){
    var form = `<form action='' class='waf-define'>
        <div class="row">
            <div class="col-md-12 form-group">
                <select class="form-control waf_policy">
                    <option value=''>${gettext('No policy')}</option>`;

    for (var i in waf_list){
        var waf = waf_list[i];
        var selected = "";
        if (waf.id === waf_id)
            selected = "selected='selected'";

        form += `<option ${selected} value='${waf.id}'>${waf.name}</option>`;
    }

    form += "</select></div></div></form>";
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
