var icon_by_type = {
    start: {
        code: "\uf0c2",
        color: "#3A444E"
    },
    frontend: {
        code: "\uf0e8",
        color: "#3A444E"
    },
    backend: {
        code: "\uf233",
        color: "#3A444E"
    },
    authentication: {
        code: "\uf007",
        color: "#3A444E"
    },
    authentication_filter: {
        code: "\uf132",
        color: "#3A444E"
    },
    acl: {
        code: "\uf023",
        color: "#3A444E"
    },
    log: {
        code: "\uf1c0",
        color: "#3A444E",
        size: 30
    },
    repo: {
        internal: vulture_logo,
        kerberos: kerberos_logo,
        radius: radius_logo,
        openid: openid_logo,
        ldap: ldap_logo,
        otp: otp_logo
    }
}

var icon_action = {
    "200": "\uf14a",
    "403": "\uf05e",
    "302": "\uf074",
    "301": "\uf074",
}

var color_action = {
    "200": "#8BC34A",
    "403": "#F44336",
    "302": "#25476A",
    "301": "#25476A"
}

var actions = {
    "200": gettext('Continue'),
    "403": gettext('403 Forbidden'),
    "302": gettext('302 Redirect'),
    "301": gettext('301 Permanent Redirect')
}

function onContentReady() {
    // bind to events
    var jc = this;
    this.$content.find('form').on('submit', function (e) {
        // if the user submits the form by pressing enter in the field.
        e.preventDefault();
        jc.$$formSubmit.trigger('click'); // reference the button and click it
    });
}

var workflow_vue = new Vue({
    el: '#workflow_vue',
    delimiters: ['${', '}'],
    data: {
        frontend_choices: [],
        backend_choices: [],
        access_control_choices: [],
        authentication_choices: [],
        authentication_filter_choices: [],
        cors_policy: {},

        workflow: [],

        id_nodes: [],
        jstree: null,

        network: null,

        workflow_mode: null,
        frontend_set: false,
        backend_set: false,
        policy_set: false,
        authentication_set: false,
        authentication_filter_set: false,

        last_node_append: null
    },

    async mounted(){
        var self = this;
        await self.get_frontends(mode=["http","tcp"])
        if (workflow_id === "None"){
            self.frontend_choices = self.frontend_choices.filter(element => element.mode == "http" || element.mode == "tcp");
            if(!self.workflow.length){
                self.workflow.push({
                    id: "#",
                    label: gettext('Start'),
                    data: {type: 'start'}
                });
                self.redraw_workflow();
                self.init_toolbox_tree();
            }
        } else {
            $.get(
                workflow_api + workflow_id + '/',
                $.param({
                    fields: ["workflow_json", "enable_cors_policy", "allowed_methods", "allowed_origins", "allowed_headers", "max_age"]
                }, true),

                function(response){
                    self.workflow = response.data.workflow_json;
                    self.cors_policy = {
                        "enable_cors_policy": response.data.enable_cors_policy,
                        "allowed_methods": response.data.allowed_methods,
                        "allowed_origins": response.data.allowed_origins,
                        "allowed_headers": response.data.allowed_headers,
                        "max_age": response.data.max_age
                    }
                    for(node of self.workflow) {
                        switch(node.data.type) {
                            case "authentication":
                                self.authentication_set = true
                                break;
                            case "authentication_filter":
                                self.authentication_filter_set = true
                                break;
                            case "frontend":
                                self.workflow_mode = node.data.mode;
                        }
                    }
                    self.get_dependencies();
                    self.frontend_set = true;
                    self.backend_set = true;
                    self.policy_set = true;
                }
            )
        }
    },

    watch: {
        backend_set(val){
            if (val)
                $('#btn-save-workflow').show();
            else
                $('#btn-save-workflow').hide();
        }
    },

    methods: {
        get_dependencies(){
            var self = this;
            return Promise.all([
                self.get_authentications(),
                self.get_authentication_filters(),
                self.get_acls(),
                self.get_backends(mode=[self.workflow_mode])
            ]).then(function(response){
                self.redraw_workflow();
                self.init_toolbox_tree();
            });

        },

        get_frontends(mode=[],enabled=true){
            var self = this;
            var data ={
                enabled : enabled,
                fields : ["mode","type","id","name","listeners","enable_logging","log_forwarders"]
            }
            if(mode)
                data.mode = mode;
            return $.get(
                frontend_services_api,
                $.param(data, true),

                function(response){
                    if (!check_json_error(response))
                        return;
                    self.frontend_choices = response.data;
                }
            )
        },

        get_backends(mode=[], enabled=true){
            var self = this;
            var data ={
                enabled : enabled,
                fields : ["mode","type","id","name","servers"]
            }
            if(mode)
                data.mode = mode;
            return $.get(
                backend_applications_api,
                $.param(data, true),

                function(response){
                    if (!check_json_error(response))
                        return;

                    self.backend_choices = response.data;
                }
            )
        },

        get_authentications(enable_external=false){
            var self = this;
            var data ={
                enable_external : enable_external,
                fields : ["id","name","repositories"]
            }
            return $.get(
                authentication_portal_api,
                $.param(data, true),
                function(response){
                    if (!check_json_error(response))
                        return;

                    self.authentication_choices = response.data;

                }
            )
        },

        get_authentication_filters(){
            var self = this;
            return $.get(
                authentication_filter_api,
                $.param({
                    fields : ["id","name"]
                }, true),
                function(response){
                    if (!check_json_error(response))
                        return;

                    self.authentication_filter_choices = response.res;
                }
            )
        },

        get_acls(){
            var self = this;
            return $.get(
                access_control_get,
                $.param({
                    fields : ["id","name"]
                }, true),
                function(response){
                    if (!check_json_error(response))
                        return;

                    self.access_control_choices = response.data;
                }
            )
        },

        workflow_save_form(){
            var self = this;

            var txt = $('#btn-save-workflow').html();
            $('#btn-save-workflow').html('<i class="fa fa-spinner fa-spin"></i>')
            $('#btn-save-workflow').prop('disabled', "disabled");

            $.post(
                '',
                {
                    workflow_enabled: $('#id_enabled').is(':checked'),
                    name: $('#id_name').val(),
                    enable_cors_policy: self.cors_policy.enable_cors_policy,
                    allowed_methods: self.cors_policy.allowed_methods,
                    allowed_origins: self.cors_policy.allowed_origins,
                    allowed_headers: self.cors_policy.allowed_headers,
                    max_age: self.cors_policy.max_age,
                    workflow: JSON.stringify(self.workflow)
                },
                function(response){
                    $('#btn-save-workflow').html(txt)
                    $('#btn-save-workflow').prop('disabled', "");

                    if (check_json_error(response)){
                        notify('success', gettext('Success'), gettext('Workflow successfully created'));
                        setTimeout(function(){
                            window.location.href = worflow_list_uri;
                        }, 300);
                    }
                }
            ).fail(function(response) {
                $('#btn-save-workflow').html(txt)
                $('#btn-save-workflow').prop('disabled', "");
                let errors = response.responseJSON.errors
                console.error(errors)
                error(errors.next())
            })
        },

        generate_id: function(){
            return Math.random().toString(36).substring(5);
        },

        error(message){
            notify('error', gettext('Error'), message);
        },

        init_folder_structure(choices, id, icon){
            var folder = [];

            for (var i in choices){
                var choice = choices[i];

                var tmp = {
                    id: id + "_" + choice.id,
                    text: choice.name,
                    data: {
                        object_id: choice.id,
                        name: choice.name,
                        type: id
                    }
                }

                switch(id){
                    case "backend":
                        tmp.data.servers = choice.servers;
                        break;

                    case "acl":
                        break;

                    case "authentication":
                        break;

                }

                folder.push(tmp)
            }

            return folder;
        },

        refresh_jstree(tree_data){
            var self = this;

            if (self.jstree){
                $('#toolbox-jstree').jstree('destroy');
                self.jstree = null;
            }

            self.jstree = $('#toolbox-jstree').jstree({
                core : {
                    data : tree_data,
                    themes:{
                        icons:false
                    }
                },
                plugins: ["search"],
                dnd: {
                    drop_target: "#workflow-visualisation",
                    is_draggable: function(node){
                        if (node[0].parent === "#")
                            return false;
                        return true;
                    }
                }
            });

            self.jstree.bind("dblclick.jstree", function (event) {
                var node = $(event.target).closest("li");
                var item = node[0].id;

                if (item === "add_access_control") {
                    window.open(access_control_add_uri, "_blank");
                } else if (item === "add_frontend") {
                    window.open(frontend_add_uri, '_blank');
                } else if (item === "add_backend") {
                    window.open(backend_add_uri, '_blank');
                } else if (item === "add_authentication") {
                    window.open(authentication_add_uri, '_blank');
                } else if (item === "add_authentication_filter") {
                    window.open(authentication_filter_add_uri, '_blank');
                } else {
                    var tree = $(this).jstree();
                    var node = tree.get_node(event.target);

                    if ($.inArray(node.id, self.id_nodes) === -1){
                        if (self.append_new_node(node))
                            self.id_nodes.push(node.id)
                    }
                }
            });
        },

        generate_frontend_tree(){
            var self = this;

            var frontends = {}
            for (var i in self.frontend_choices){
                var frontend = self.frontend_choices[i];
                frontend.type = "frontend";

                if (!frontends[frontend.mode])
                    frontends[frontend.mode] = []

                frontends[frontend.mode].push({
                    id: "frontend_"+frontend.id,
                    text: frontend.name,
                    data: {
                        object_id: frontend.id,
                        listeners: frontend.listeners,
                        type: 'frontend',
                        mode: frontend.mode
                    }
                })
            }

            var data = {
                text: "<i class='fa fa-sitemap'>&nbsp;&nbsp;</i>"+gettext('Listeners'),
                state: {opened: true},
                children: []
            }

            $.each(frontends, function(key, value){
                data.children.push({
                    text: key.toUpperCase(),
                    children: value,
                    state: {opened: true}
                })
            })

            data.children.push({
                id: "add_frontend",
                text: "<i class='fa fa-plus'></i>&nbsp;" + gettext("Add")
            })

            return data;
        },

        generate_acl_tree(){
            var self = this;

            var access_controls = self.init_folder_structure(self.access_control_choices, "acl", " ");

            access_controls.push({
                id: "add_access_control",
                text: "<i class='fa fa-plus'></i>&nbsp;" + gettext("Add")
            })

            return {
                text: "<i class='fa fa-eye'>&nbsp;&nbsp;</i>"+gettext('ACLS'),
                state: {opened: true},
                children: access_controls,
                icon: "fas fa-universal-access"
            }
        },

        generate_authentication_tree(){
            var self = this;

            var authentications = self.init_folder_structure(self.authentication_choices, "authentication", " ");
            authentications.push({
                id: "add_authentication",
                text: `<i class='fa fa-plus'></i>&nbsp;${gettext('Add')}`
            })

            return {
                text: `<i class="fa fa-user">&nbsp;&nbsp;</i>${gettext("Authentication")}`,
                state: {opened: true},
                children: authentications,
                icon: "fa fa-user"
            }
        },

        generate_authentication_filter_tree(){
            var self = this;

            var authentication_filters = self.init_folder_structure(self.authentication_filter_choices, "authentication_filter", " ");
            authentication_filters.push({
                id: "add_authentication_filter",
                text: "<i class='fa fa-plus'></i>&nbsp;" + gettext("Add")
            })
            return {
                text: "<i class='fa fa-shield'>&nbsp;&nbsp;</i>"+gettext('Authentication Scope Filters'),
                state: {opened: true},
                children: authentication_filters,
                icon: 'fa fa-shield'
            }
        },

        generate_backend_tree(){
            var self = this;

            var backends = self.init_folder_structure(self.backend_choices, "backend", " ");
            backends.push({
                id: "add_backend",
                text: "<i class='fa fa-plus'></i>&nbsp;" + gettext("Add")
            })
            return {
                text: "<i class='fa fa-server'>&nbsp;&nbsp;</i>"+gettext('Backends'),
                state: {opened: true},
                children: backends,
                icon: 'fa fa-server'
            }
        },

        init_toolbox_tree(){
            var self = this;
            var tree_data = [];

            if (!self.frontend_set){
                tree_data.push(this.generate_frontend_tree());
            } else if (!self.backend_set){
                tree_data.push(this.generate_acl_tree());
                if (!self.authentication_set){
                    tree_data.push(this.generate_authentication_tree());
                } else {
                    if(!self.authentication_filter_set) {
                        tree_data.push(this.generate_authentication_filter_tree());
                    }
                }
                tree_data.push(this.generate_backend_tree());
            }
            this.refresh_jstree(tree_data);
        },

        check_action(action_satisfy, action_not_satisfy, redirect_url_satisfy, redirect_url_not_satisfy){
            if (!action_satisfy && !action_not_satisfy){
                this.error(gettext('Please provide action for ACL'))
                return false;
            }

            if ($.inArray(action_satisfy, ["301", "302"]) > -1){
                if (!redirect_url_satisfy){
                    this.error(gettext('Please provide an URL to redirect to'))
                    return false;
                }
            }

            if ($.inArray(action_not_satisfy, ["301", "302"]) > -1){
                if (!redirect_url_not_satisfy){
                    this.error(gettext('Please provide an URL to redirect to'))
                    return false;
                }
            }

            if (action_satisfy === action_not_satisfy){
                this.error(gettext("Please provide different action"))
                return false;
            }

            if ($.inArray("200", [action_satisfy, action_not_satisfy]) === -1){
                this.error(gettext('At least one action must be continue'))
                return false;
            }

            return true;
        },

        get_actions(acl_node){
            var actions = {}
            for (var i in this.workflow){
                var tmp_node = this.workflow[i];
                if (tmp_node.parent === acl_node.id)
                    actions[i] = tmp_node;
            }

            return actions;
        },

        define_acl(node, acl_id, action_satisfy, action_not_satisfy, redirect_url_satisfy, redirect_url_not_satisfy){
            var self = this;
            node.data.object_id = acl_id;

            var actions = self.get_actions(node);

            $.each(actions, function(index_action, action){
                if (action.data.satisfy){
                    action.data.action = action_satisfy;
                    action.data.redirect_url = redirect_url_satisfy;
                } else {
                    action.data.action = action_not_satisfy;
                    action.data.redirect_url = redirect_url_not_satisfy;
                }
            })

            for (var i in self.access_control_choices){
                var acl = self.access_control_choices[i];
                if (acl.id === acl_id){
                    node.data.name = acl.name;
                    node.label = acl.name;
                    break;
                }
            }

            node.data.action_satisfy = action_satisfy;
            node.data.action_not_satisfy = action_not_satisfy;
            node.data.redirect_url_satisfy = redirect_url_satisfy;
            node.data.redirect_url_not_satisfy = redirect_url_not_satisfy;

            var index_acl = self.get_node(node.id, true);
            self.workflow[index_acl] = node;

            var step_id_200;
            var step_id_not_200;
            for (var i in self.workflow){
                var step = self.workflow[i];
                if (step.data.type === "action"){
                    if (step.data.action === "200"){
                        step_id_200 = step.id;
                    } else {
                        step_id_not_200 = step.id;
                    }
                }
            }

            for (var i in self.workflow){
                var step = self.workflow[i];

                if (step.parent === step_id_not_200){
                    self.workflow[i].parent = step_id_200;
                }
            }

            self.redraw_workflow();
        },

        append_frontend(frontend_node){
            var self = this;

            async function append_frontend_to_workflow(node){
                self.workflow.push(frontend_node)
                self.frontend_set = true;

                self.last_node_append = frontend_node.id;
                await self.get_dependencies();
            }

            if (frontend_node.data.mode === "http"){
                $.confirm({
                    title: gettext('Define FQDN & Public Directory'),
                    columnClass: 'medium',
                    content: form_frontend(false),
                    buttons: {
                        formSubmit: {
                            text: gettext('Save'),
                            btnClass: 'btn-blue',
                            action: function () {
                                let fqdn = this.$content.find('.fqdn').val();
                                let public_dir = this.$content.find('.public_dir').val();
                                if (!fqdn){
                                    $.alert(gettext("Please provide FQDN to reach your application"))
                                    return false;
                                }

                                frontend_node.data.fqdn = fqdn;
                                frontend_node.data.public_dir = public_dir;
                                self.workflow[0].label = fqdn + public_dir;
                                self.cors_policy.enable_cors_policy = this.$content.find('#id_enable_cors_policy').is(':checked');
                                self.cors_policy.allowed_methods = this.$content.find('#id_allowed_methods').val();
                                self.cors_policy.allowed_origins = this.$content.find('#id_allowed_origins').val();
                                self.cors_policy.allowed_headers = this.$content.find('#id_allowed_headers').val();
                                self.cors_policy.max_age = this.$content.find('#id_max_age').val();

                                append_frontend_to_workflow(frontend_node)
                                return;
                            }
                        },
                        cancel: function () {
                            //close
                            return true;
                        }
                    },
                    onContentReady: function () {
                        this.$content.find('.select2').select2({dropdownParent: $(".jconfirm")});
                        new Switchery(this.$content.find('.js-switch')[0]);
                    }
                })
            } else {
                // Define what to do with other type of frontends
                append_frontend_to_workflow(frontend_node)
            }
        },

        append_acl(acl_node){
            var self = this;

            $.confirm({
                title: gettext('Access Control'),
                columnClass: 'large',
                content: form_acl(self.workflow_mode),
                buttons: {
                    formSubmit: {
                        text: gettext('Save'),
                        btnClass: 'btn-blue',
                        action: function () {
                            var action_satisfy = this.$content.find('.action_satisfy').val();
                            var action_not_satisfy = this.$content.find('.action_not_satisfy').val();

                            var redirect_url_satisfy = this.$content.find('.redirect_url_satisfy').val();
                            var redirect_url_not_satisfy = this.$content.find('.redirect_url_not_satisfy').val();

                            if (!self.check_action(action_satisfy, action_not_satisfy, redirect_url_satisfy, redirect_url_not_satisfy))
                                return false;

                            acl_node.parent = self.last_node_append;
                            acl_node.data.action_satisfy = action_satisfy;
                            acl_node.data.action_not_satisfy = action_not_satisfy;
                            acl_node.data.redirect_url_satisfy = redirect_url_satisfy;
                            acl_node.data.redirect_url_not_satisfy = redirect_url_not_satisfy;

                            self.workflow.push(acl_node)

                            var node_acl_satisfy = {
                                id: acl_node.id + "_" + "satisfy_" + self.generate_id(),
                                parent: acl_node.id,
                                data: {
                                    type: 'action',
                                    satisfy: true,
                                    action: action_satisfy,
                                    redirect_url: redirect_url_satisfy
                                }
                            }

                            var node_acl_not_satisfy = {
                                id: acl_node.id + "_" + "not_satisfy_" + self.generate_id(),
                                parent: acl_node.id,
                                data: {
                                    type: 'action',
                                    satisfy: false,
                                    action: action_not_satisfy,
                                    redirect_url: redirect_url_not_satisfy
                                }
                            }

                            if (action_satisfy === "200")
                                self.last_node_append = node_acl_satisfy.id;
                            else if (action_not_satisfy === "200")
                                self.last_node_append = node_acl_not_satisfy.id;

                            self.workflow.push(node_acl_satisfy);
                            self.workflow.push(node_acl_not_satisfy);

                            self.redraw_workflow();
                            return;
                        }
                    },
                    cancel: function () {
                        //close
                        return true;
                    },
                },
                onContentReady: onContentReady
            });
        },

        append_new_node(node){
            PNotify.removeAll();

            var self = this;
            var node_type = node.data.type;

            var tmp = {
                id: self.generate_id(),
                data: node.data,
                parent: self.last_node_append
            }

            tmp.data.type = node_type;

            switch(node_type){
                case "frontend":
                    tmp.parent = "#";
                    self.workflow_mode = node.data.mode;
                    self.append_frontend(tmp);
                    break;

                case "acl":
                    tmp.label = node.data.name;
                    self.append_acl(tmp);
                    break;

                case "authentication":
                    tmp.label = node.data.name;
                    self.workflow.push(tmp);
                    self.last_node_append = tmp.id;
                    self.authentication_set = true;
                    self.redraw_workflow();
                    break;

                case "authentication_filter":
                    tmp.label = node.data.name;
                    self.workflow.push(tmp);
                    self.last_node_append = tmp.id;
                    self.authentication_filter_set = true;
                    self.redraw_workflow();
                    break;

                case "backend":
                    self.workflow.push(tmp);
                    self.last_node_append = tmp.id;
                    self.backend_set = true;
                    self.redraw_workflow();
                    break;
            }
        },

        get_node(node_id, index){
            for (var i in this.workflow){
                if (this.workflow[i].id === node_id){
                    if (index)
                        return i;

                    return this.workflow[i];
                }
            }

            return false;
        },

        remove_children(parent_id){
            var indices_to_remove = [];
            for (var i in this.workflow){
                var node = this.workflow[i];
                if (node.parent === parent_id){
                    indices_to_remove.push(node.id);
                    var tmp_indice = this.remove_children(node.id);
                    for (var j in tmp_indice)
                        indices_to_remove.push(tmp_indice[j]);
                }
            }

            return indices_to_remove;
        },

        redraw_workflow(){
            var self = this;

            var nodes = [];
            var edges = [];

            for (var i in self.workflow){
                var step = self.workflow[i];

                var tmp = {
                    id: step.id,
                    shape: "icon",
                    label: step.label,
                    icon: icon_by_type[step.data.type]
                }

                switch(step.data.type){
                    case "frontend":
                        for (var i in self.frontend_choices){
                            var f = self.frontend_choices[i];

                            if (f.id === step.data.object_id){
                                var label = ["\n"];
                                for (var j in f.listeners){
                                    var listener = f.listeners[j];

                                    if (j > 1){
                                        label.push("...");
                                        break;
                                    }

                                    var mode = f.mode;
                                    if (mode === "http"){
                                        if (listener.is_tls)
                                            mode = "https"
                                    }

                                    label.push(mode + "://" + listener.addr_port)
                                }

                                tmp.label = label.join('\n');

                                if (f.enable_logging){
                                    var node_tmp = {
                                        id: "logging_node",
                                        shape: 'icon',
                                        icon: icon_by_type['log']
                                    }

                                    var label = ["\n"];
                                    for (var j in f.log_forwarders){
                                        if (j > 1){
                                            label.push('...');
                                            break;
                                        }

                                        var log = f.log_forwarders[j];
                                        label.push(log.type + " - " + log.name)
                                    }

                                    node_tmp.label = label.join('\n');
                                    nodes.push(node_tmp)

                                    edges.push({
                                        from: step.id,
                                        to: "logging_node",
                                        dashes: true,
                                        arrows: 'to',
                                        length: 200,
                                        label: gettext('Logs'),
                                        font: {align: 'bottom'}
                                    })
                                }

                                break;
                            }
                        }
                        break;
                    case "action":
                        if (step.data.action === "403")
                            tmp.label = forbidden_html[self.workflow_mode]
                        else
                            tmp.label = actions[step.data.action];

                        if ($.inArray(step.data.action, ['301', '302']))
                            tmp.label += "\n" + step.data.redirect_url;

                        tmp.icon = {
                            code: icon_action[step.data.action],
                            color: color_action[step.data.action],
                            size: 20
                        }
                        break;
                    case "authentication":
                        for (let auth of self.authentication_choices){
                            if (auth.id === step.data.object_id){
                                step.data.name = auth.name;
                                for (let repo of auth.repositories){
                                    let image = icon_by_type.repo[repo.subtype]
                                    if (!image)
                                        image = vulture_logo

                                    let node_tmp = {
                                        id: `repo_node_${repo.id}`,
                                        label: repo.name,
                                        shape: "image",
                                        image: image
                                    }

                                    nodes.push(node_tmp)
                                    edges.push({
                                        from: step.id,
                                        to: `repo_node_${repo.id}`,
                                        dashes: true,
                                        arrows: 'to',
                                        length: 300,
                                        label: gettext('Repository'),
                                        font: {align: 'bottom'}
                                    })
                                }
                            }
                        }

                        if (!tmp.label)
                            tmp.label = step.data.name
                        break;
                    case "authentication_filter":
                        if (!tmp.label)
                            tmp.label = step.data.name
                        break;
                    case "backend":
                        for (var i in self.backend_choices){
                            var b = self.backend_choices[i];
                            if (b.id === step.data.object_id){
                                var label = ["\n"];
                                for (var j in b.servers){
                                    var server = b.servers[j];

                                    if (j > 1){
                                        label.push("...");
                                        break;
                                    }

                                    var mode = b.mode;
                                    if (mode === "http"){
                                        if (server.tls_profile)
                                            mode = "https"
                                    }

                                    label.push(mode + "://" + server.target + ":" + server.port);
                                }

                                tmp.label = label.join('\n');
                                break;
                            }
                        }
                        break;
                }

                nodes.push(tmp)

                if (step.parent){
                    var tmp = {
                        from: step.parent,
                        color: {
                            color: "#3A444E"
                        },
                        arrows: 'to',
                        to: step.id,
                        width: 1
                    }

                    if (step.data.type === "action"){
                        if (!step.data.satisfy){
                            tmp.label = "NOK";
                            tmp.font = {align: 'middle'},
                            tmp.color = {
                                color: "#F44336"
                            };
                        } else if (step.data.satisfy){
                            tmp.label = "OK";
                            tmp.font = {align: 'middle'},
                            tmp.color = {
                                color: "#8BC34A"
                            };
                        }
                    }

                    edges.push(tmp)
                }
            }

            var data = {
                nodes: new vis.DataSet(nodes),
                edges: new vis.DataSet(edges)
            };

            var container = document.getElementById('workflow-visualisation');
            var options = {
                layout: {
                    hierarchical: {
                        direction: "LR"
                    }
                },
                manipulation: {
                    enabled: true,
                    addNode: false,
                    initiallyActive: true,
                    addEdge: false,
                    editNode: function(data, callback){
                        PNotify.removeAll();

                        var node = self.get_node(data.id);

                        if (!node.data){
                            callback();
                            return;
                        }

                        var node_type = node.data.type;
                        if (node_type === "start"){
                            node_type = "frontend";
                            for (var i in self.workflow){
                                var step = self.workflow[i];
                                if (step.data.type === "frontend"){
                                    node = step;
                                    break;
                                }
                            }
                        } else if (node_type === "action"){
                            node_type = "acl";
                            for (var i in self.workflow){
                                var step = self.workflow[i];
                                if (step.id === node.parent){
                                    node = step;
                                    break;
                                }
                            }
                        }

                        switch(node_type){
                            case "frontend":
                                $.confirm({
                                    title: gettext('Listener'),
                                    columnClass: 'medium',
                                    content: form_frontend(true, self.cors_policy, self.frontend_choices, node.data.object_id, self.workflow_mode, node.data.fqdn, node.data.public_dir),
                                    buttons: {
                                        formSubmit: {
                                            text: gettext('Save'),
                                            btnClass: 'btn-blue',
                                            action: function () {
                                                var frontend_id = this.$content.find('.frontend').val();
                                                var fqdn = this.$content.find('.fqdn').val();
                                                var public_dir = this.$content.find('.public_dir').val();
                                                if (!fqdn){
                                                    $.alert(gettext("Please provide FQDN to reach your application"))
                                                    return false;
                                                }

                                                node.data.fqdn = fqdn;
                                                node.data.public_dir = public_dir;
                                                node.data.object_id = frontend_id
                                                self.workflow[0].label = fqdn + public_dir;
                                                self.cors_policy.enable_cors_policy = this.$content.find('#id_enable_cors_policy').is(':checked');
                                                self.cors_policy.allowed_methods = this.$content.find('#id_allowed_methods').val();
                                                self.cors_policy.allowed_origins = this.$content.find('#id_allowed_origins').val();
                                                self.cors_policy.allowed_headers = this.$content.find('#id_allowed_headers').val();
                                                self.cors_policy.max_age = this.$content.find('#id_max_age').val();

                                                var index_frontend = self.get_node(node.id, true);
                                                self.workflow[index_frontend] = node;
                                                self.redraw_workflow();
                                            }
                                        },
                                        cancel: function () {
                                            //close
                                            return true;
                                        }
                                    },
                                    onContentReady: function () {
                                        this.$content.find('.select2').select2({dropdownParent: $(".jconfirm")});
                                        new Switchery(this.$content.find('.js-switch')[0]);
                                    }
                                })
                                break;
                            case "acl":
                                var actions = self.get_actions(node);

                                var form = form_acl(
                                    self.workflow_mode,
                                    true,
                                    self.access_control_choices,
                                    node.data.object_id,
                                    node.data.action_satisfy,
                                    node.data.redirect_url_satisfy,
                                    node.data.action_not_satisfy,
                                    node.data.redirect_url_not_satisfy
                                )

                                $.confirm({
                                    title: gettext('Access Control List'),
                                    columnClass: 'large',
                                    content: form,
                                    buttons: {
                                        formSubmit: {
                                            text: gettext('Save'),
                                            btnClass: 'btn-blue',
                                            action: function () {
                                                var acl_id = this.$content.find('.access_control').val();
                                                var action_satisfy = this.$content.find('.action_satisfy').val();
                                                var action_not_satisfy = this.$content.find('.action_not_satisfy').val();

                                                var redirect_url_satisfy = this.$content.find('.redirect_url_satisfy').val();
                                                var redirect_url_not_satisfy = this.$content.find('.redirect_url_not_satisfy').val();

                                                if (!self.check_action(action_satisfy, action_not_satisfy, redirect_url_satisfy, redirect_url_not_satisfy))
                                                    return false;

                                                self.define_acl(node, acl_id, action_satisfy, action_not_satisfy, redirect_url_satisfy, redirect_url_not_satisfy)
                                            }
                                        },
                                        cancel: function(){
                                            return true;
                                        },
                                    },
                                    onContentReady: onContentReady
                                });
                                break;

                            case "authentication":
                                $.confirm({
                                    title: gettext('Authentication Portal'),
                                    columnClass: "medium",
                                    content: form_authentication(self.authentication_choices, node.data.object_id),
                                    buttons: {
                                        formSubmit: {
                                            text: gettext('Save'),
                                            btnClass: 'btn-blue',
                                            action: function(){
                                                var authentication_id = this.$content.find('.authentication').val();
                                                if(authentication_id !== '') {
                                                    node.data.object_id = authentication_id;
                                                    for (choice of self.authentication_choices){
                                                        if (choice.id === authentication_id){
                                                            node.label = choice.name;
                                                            node.data.name = choice.name;
                                                        }
                                                    }
                                                }
                                                else {
                                                    node.data.object_id = null;
                                                    node.label = "No authentication";
                                                    node.data.name = "No authentication";
                                                }

                                                var index_authentication = self.get_node(data.id, true);
                                                self.workflow[index_authentication] = node;
                                                self.redraw_workflow();
                                            }
                                        },
                                        cancel: function(){
                                            return true;
                                        }
                                    }
                                })
                                break;
                            case "authentication_filter":
                                $.confirm({
                                    title: gettext('Authentication Filter Scopes'),
                                    columnClass: "medium",
                                    content: form_authentication_filter(self.authentication_filter_choices, node.data.object_id),
                                    buttons: {
                                        formSubmit: {
                                            text: gettext('Save'),
                                            btnClass: 'btn-blue',
                                            action: function(){
                                                var authentication_filter_id = this.$content.find('.authentication_filter').val();
                                                if(authentication_filter_id !== '') {
                                                    node.data.object_id = authentication_filter_id;
                                                    for (choice of self.authentication_choices){
                                                        if (choice.id === authentication_filter_id){
                                                            node.label = choice.name;
                                                            node.data.name = choice.name;
                                                        }
                                                    }
                                                }
                                                else {
                                                    node.data.object_id = null;
                                                    node.label = "No authentication";
                                                    node.data.name = "No authentication";
                                                }


                                                var index_authentication_filter = self.get_node(data.id, true);
                                                self.workflow[index_authentication_filter] = node;
                                                self.redraw_workflow();
                                            }
                                        },
                                        cancel: function(){
                                            return true;
                                        }
                                    }
                                })
                                break;
                            case "backend":
                                $.confirm({
                                    title: gettext('Applications'),
                                    columnClass: "medium",
                                    content: form_backend(self.backend_choices, node.data.object_id),
                                    buttons: {
                                        formSubmit: {
                                            text: gettext('Save'),
                                            btnClass: 'btn-blue',
                                            action: function(){
                                                var backend_id = this.$content.find('.backend').val();

                                                node.data.object_id = backend_id;

                                                var index_backend = self.get_node(data.id, true);
                                                self.workflow[index_backend] = node;
                                                self.redraw_workflow();
                                            }
                                        },
                                        cancel: function(){
                                            return true;
                                        }
                                    }
                                })
                                break;
                        }
                        callback();
                    },
                    editEdge: false,
                    deleteEdge: false,
                    deleteNode: function(data, callback){
                        PNotify.removeAll();
                        if (data.nodes.length > 1){
                            self.error(gettext("You can't delete several nodes at once"))
                            callback();
                            return false;
                        }

                        var node_id = data.nodes[0];
                        var node_to_delete = self.get_node(node_id);
                        self.last_node_append = node_to_delete.parent;

                        if (!node_to_delete.data){
                            callback();
                            return;
                        }

                        switch(node_to_delete.data.type){
                            case "start":
                                callback();
                                return false;
                            case "frontend":
                                self.frontend_set = false;
                                self.backend_set = false;
                                self.workflow_mode = null;
                                break;
                            case "backend":
                                self.backend_set = false;
                                break;
                            case "authentication":
                                self.backend_set = false;
                                self.authentication_filter_set = false;
                                break;
                            case "authentication_filter":
                                self.backend_set = false;
                                self.authentication_filter_set = false;
                                break;
                            case "action":
                                self.error(gettext("An action can not be deleted. Delete the Access Control instead."))
                                callback();
                                return false;
                        }

                        for (var i in self.workflow){
                            var node = self.workflow[i];
                            if (node.id === node_id){
                                indices_to_remove = self.remove_children(node.id);
                                indices_to_remove.push(node.id)
                            }
                        }

                        for (var i in indices_to_remove){
                            var id = indices_to_remove[i];
                            indice = self.get_node(id, true);
                            var node = self.get_node(id);
                            if (node.data.type === "frontend")
                                self.frontend_set = false;
                            else if (node.data.type === "backend")
                                self.backend_set = false;
                            else if (node.data.type === "authentication"){
                                self.authentication_set = false;
                            }
                            else if (node.data.type === "authentication_filter")
                                self.authentication_filter_set = false;

                            self.workflow.splice(indice, 1);
                        }

                        self.init_toolbox_tree();
                        self.redraw_workflow();
                        callback();
                    }
                }
            }

            self.network = new vis.Network(container, data, options);
            setTimeout(function(){
                self.init_toolbox_tree();
            }, 50)
        }
    }
})


$(function(){
    $('#search-toolbox-btn').on('click', function(){
        workflow_vue.search_toolbox($('#search-toolbox').val());
    })

    $('#search-toolbox').on('keyup', function(e){
        if (e.keyCode == 13)
            workflow_vue.search_toolbox($('#search-toolbox').val());
    })

    $('#workflow_save_form').on('submit', function(e){
        e.preventDefault();
        workflow_vue.workflow_save_form();
    })

    $('#block-tree').matchHeight({
        target: $('#block-visualisation')
    });

    new Switchery(document.querySelector('.js-switch'));
})