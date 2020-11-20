const name_choices = {
    'hdr': [
        "Accept", "Accept-Charset", "Accept-Encoding", "Accept-Language", "Accept-Datetime", "Authorization", 
        "Cache-Control", "Connection", "Cookie", "Content-Length", "Content-MD5", "Content-Type", "Date", "DNT", "Expect", "From", 
        "Front-End-Https", "Host", "If-Match", "If-Modified-Since", "If-None-Match", "If-Range", "If-Unmodified-Since", 
        "Max-Forwards", "Origin", "Pragma", "Proxy-Authorization", "Proxy-Connection", "Range", "Referer", "TE", "User-Agent", 
        "Upgrade", "Via", "Warning", "X-Requested-With", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", 
        "X-Http-Method-Override", "X-ATT-DeviceId", "X-Wap-Profile"
    ],

    "shdr": [
        "Access-Control-Allow-Origin", "Accept-Ranges", "Age", 
        "Allow", "Cache-Control", "Connection", "Content-Encoding", "Content-Language", "Content-Length", "Content-Location", 
        "Content-MD5", "Content-Disposition", "Content-Range", "Content-Type", "Date", "ETag", "Expires", "Last-Modified", "Link", 
        "Location", "P3P", "Pragma", "Proxy-Authenticate", "Public-Key-Pins", "Refresh", "Retry-After", "Server", "Set-Cookie", 
        "Status", "Strict-Transport-Security", "Trailer", "Transfer-Encoding", "Upgrade", "Vary", "Via", "Warning", "WWW-Authenticate",
        "X-Frame-Options", "X-XSS-Protection", "Content-Security-Policy", "X-Content-Type-Options", "X-Powered-By", "X-UA-Compatible"
    ],
    'urlp': [],
    'cook': [],
    'scook': [],
    'http_auth_group': []
};

const criterion_html = {
    "src": gettext('Source IP'),
    "base": gettext('Base'),
    "hdr": gettext('Request Header'),
    "shdr": gettext('Response Header'),
    "http_auth_group": gettext('Authentication group'),
    "method": gettext('Method'),
    "path": gettext('Path'),
    "url": gettext('URL'),
    "urlp": gettext('URLP'),
    "cook": gettext('Request Cookie'),
    "scook": gettext('Response Cookie'),
    "rdp_cookie": gettext('RDP Cookie')
}

const converter_html = {
    "beg": gettext("Prefix match"),
    "dir": gettext("Subdir match"),
    "dom": gettext("Domain match"),
    "end": gettext("Suffix match"),
    "hex": gettext("Hex block"),
    "int": gettext("Integer match"),
    "ip": gettext("IP address match"),
    "len": gettext("Length match"),
    "reg": gettext("Regex match"),
    "str": gettext("Exact string match"),
    "sub": gettext("Substring match"),
    "found": gettext("Found"),
}

const operator_html = {
    "eq": gettext('Equal'),
    "ge": gettext('Greater than or Equal'),
    "gt": gettext('Greater than'),
    "le": gettext('Lesser than or Equal'),
    "lt": gettext('Lesser than'),
}

var access_control_vue;

function init_interface(){
    $('.converter').unbind('change');
    setTimeout(function(){
        $('.converter').on('change', function(){
            var converter_value = $(this).val();
            if ($.inArray(converter_value, ['int', 'len']) > -1){
                $('.nooperator').hide();
                $('.operator').show();
            } else {
                $('.operator').hide();
                $('.nooperator').show();
            }
        }).trigger('change')
    }, 100)

    $('.reload').unbind('change');
    $('.reload').on('change', function(){
        access_control_vue.render_rule();
        access_control_vue.reconstruct_rules();
    })


    $('.criterion').unbind('change');
    setTimeout(function(){
        $('.pattern').unbind('keyup')
        $('.pattern').on('keyup', function(){
            access_control_vue.render_rule();
            access_control_vue.reconstruct_rules();
        })

        $(".criterion").on('change', function(){
            let value = $(this).val();
            let tr = $(this).parent('td').parent('tr');

            let name_input = $(tr).find('.criterion_name');

            if ($.inArray(value, Object.keys(name_choices)) > -1){
                $(name_input).tagsinput({
                    maxTags: 1,
                    freeInput: true,
                    typeaheadjs: {
                        minLength: 0,
                        freeInput: true,
                        name: "choices",
                        source: function(query, syncResults){

                            var choices = [];
                            for (var i in name_choices[value]){
                                var tmp = name_choices[value][i];
                                if (tmp.startsWith(query))
                                    choices.push(tmp)
                            }
                            syncResults(choices);
                        }
                    }
                });
            } else {
                $(name_input).tagsinput('removeAll');
                $(name_input).tagsinput('destroy');
                $(name_input).hide();
            }

        }).trigger('change');
    }, 100)
}

access_control_vue = new Vue({
    el: '#access_control_vue',
    delimiters: ['${', '}'],
    data: {
        or_lines: [],
        rule: ""
    },

    methods: {
        is_selected: function(type, line, value){
            if ($.inArray(type, ['dns', 'case']) > -1){
                if (line[type])
                    return "checked";
            } else {
                if (line[type] === value)
                    return "selected";
            }
        },

        generate_id: function(){
            return Math.random().toString(36).substring(5);
        },

        render_and: function(index){
            if (index > 0)
                return '<label class="label label-primary">AND</label>';
        },

        render_rule: function(){
            if (jQuery.isEmptyObject(this.or_lines))
                return;

            let rule = "if ";
            let acls = [];
            let tmp_acls_or = [];

            for (var j in this.or_lines){
                var or_line = this.or_lines[j];

                if (!or_line.lines.length)
                    continue;

                var acls_names = [];
                for (var i in or_line.lines){
                    var name = this.generate_id();
                    var acl_and = "acl " + name;
                    acls_names.push(name)
                    var and_line = or_line.lines[i];

                    var flags = [];
                    if (and_line.dns)
                        flags.push("-n");

                    if (and_line.case)
                        flags.push("-i");

                    acl_and += ` ${and_line.criterion}`;
                    if (and_line.criterion_name)
                        acl_and += `(${and_line.criterion_name})`;

                    acl_and += ` -m ${and_line.converter} ${flags.join(' ')}`;

                    if (and_line.operator)
                        acl_and += ` ${and_line.operator} `;

                    acl_and += `${and_line.pattern}`;
                    acls.push(acl_and)
                }

                tmp_acls_or.push(acls_names)
            }

            var acl_html = acls.join('\n');

            var ands = [];
            for (var i in tmp_acls_or){
                ands.push("("+tmp_acls_or[i].join(' and ')+")");
            }

            rule += ands.join(' or ');
            this.rule = acl_html + "\n\n" + rule;
        },

        get_or_index: function(or_id){
            for (let i in this.or_lines){
                if (this.or_lines[i].pk === or_id)
                    return i;
            }
        },

        check_acl: function(acl){
            PNotify.removeAll();

            if (!acl.converter)
                return 'converter';

            if (!acl.criterion)
                return 'criterion'

            if ($.inArray(acl.converter, ['beg', 'dir', 'dom', 'end', 'len', 'reg', 'sub']) > -1){
                if (!acl.pattern)
                    return 'pattern';
            }

            return null;
        },

        render_error(error, input){
            if (!input){
                if (error)
                    return "<i class='fas fa-exclamation-triangle fa-2x'></i>";
                return "";
            }

            if (input === error)
                return "<i class='fas fa-exclamation-triangle'></i>&nbsp;&nbsp;&nbsp;" + gettext('This input is mandatory');
        },

        render_class_end_line: function(error){
            var classe = "and_line";

            if (error)
                classe += " and_line_error";

            return classe;
        },

        add_or: function(){
            let pk = this.generate_id();
            this.or_lines.push({
                pk: pk,
                lines: []
            });

            this.render_rule();
            this.add_and(pk);
        },

        remove_or: function(or_id){
            let index = this.get_or_index(or_id);
            this.or_lines.splice(index, 1);

            this.render_rule();
        },

        render_id: function(or_index, and_index){
            return `and_line_${or_index}_${and_index}`;
        },

        reconstruct_rules: function(){
            var self = this;
            $('.condition_block').each(function(){
                var or_index = $(this).data('index');
                $(this).find('.and_line').each(function(){
                    var and_index = $(this).data('index');
                    var and_line = self.or_lines[or_index].lines[and_index];

                    let tr = $(`#and_line_${or_index}_${and_index}`);

                    and_line.criterion = $(tr).find('.criterion').val();
                    and_line.criterion_name = $(tr).find('.criterion_name').val();
                    and_line.converter = $(tr).find('.converter').val();
                    and_line.operator = $(tr).find('.operator').val();
                    and_line.pattern = $(tr).find('.pattern').val();
                    and_line.dns = $(tr).find('.dns').is(':checked');
                    and_line.case = $(tr).find('.case').is(':checked');

                    and_line.error = self.check_acl(and_line)

                    self.or_lines[or_index].lines[and_index] = and_line;
                })
            })
        },

        add_and: function(or_id){
            var self = this;
            let index = self.get_or_index(or_id);

            self.reconstruct_rules();

            this.or_lines[index].lines.push({
                acl_name: self.generate_id(),
                criterion: "",
                criterion_name: "",
                converter: "",
                dns: true,
                case: false,
                operator: "",
                pattern: "",
                error: null
            });

            init_interface();
        },

        remove_and: function(or_id, and_index){
            let index = this.get_or_index(or_id);
            this.or_lines[index].lines.splice(and_index, 1);

            this.render_rule();
        },

        save_form: function(){
            var txt = $('#save_form_btn').html();
            $('#save_form_btn').html('<i class="fa fa-spinner fa-spin"></i>');
            $('#save_form_btn').prop('disabled', 'disabled');

            var self = this;

            self.reconstruct_rules();
            self.render_rule();

            for (var or_line of self.or_lines){
                for (var and_line of or_line.lines){
                    if (self.check_acl(and_line) !== null)
                        return false;
                }
            }

            var data = {
                or_lines: JSON.stringify(self.or_lines),
                rule: self.rule,
                name: $('#id_name').val().replace(/ /g, '_'),
                enabled: $('#id_enabled').is(':checked')
            };

            serialize = function(obj) {
                var str = [];
                for (var p in obj)
                    if (obj.hasOwnProperty(p)) {
                        str.push(encodeURIComponent(p) + "=" + encodeURIComponent(obj[p]));
                    }
                return str.join("&");
            };

            let data2 = serialize(data);

            $.ajax({
                url: '',
                data: data2,
                processData: false,
                type: "POST",
            }).done(
                function(response){
                    $('#save_form_btn').html(txt);
                    $('#save_form_btn').prop('disabled', '');
                    if (check_json_error(response)){
                        notify('success', gettext('Success', response.message));

                        setTimeout(function(){
                            window.location.href = access_control_list_uri;
                        }, 1000);
                    }
                }
            )
        }
    },

    updated: function(){
        $('.condition_block').each(function(){
            var index = parseInt($(this).data('index'));
            if ($(this).css('marginLeft') !== 0){
                $(this).css('marginLeft', index*50 + "px");
            }
        })
    },

    mounted: function(){
        var self = this;

        if (pk_acl){
            $.post(
                access_control_get_uri,
                {'pk': pk_acl},

                function(response){
                    if (check_json_error(response)){
                        self.or_lines = JSON.parse(response.acl.rules);
                        init_interface();
                        self.render_rule();
                    }
                }
            )
        } else if (log_id !== "None") {
            $.post(
                access_control_get_uri,
                {'log_id': log_id},

                function(response){
                    if (check_json_error(response)){
                        var rules = [{
                            pk: self.generate_id(),
                            lines: [{
                                acl_name: self.generate_id(),
                                criterion: "src_ip",
                                criterion_name: "",
                                converter: "ip",
                                dns: true,
                                case: false,
                                operator: "",
                                pattern: response.log_line.src_ip,
                                error: null
                            }, {
                                acl_name: self.generate_id(),
                                criterion: "method",
                                criterion_name: "",
                                converter: "str",
                                dns: true,
                                case: false,
                                operator: "",
                                pattern: response.log_line.http_method,
                                error: null
                            }, {
                                acl_name: self.generate_id(),
                                criterion: "url",
                                criterion_name: "",
                                converter: "str",
                                dns: true,
                                case: false,
                                operator: "",
                                pattern: response.log_line.http_path,
                                error: null
                            }, {
                                acl_name: self.generate_id(),
                                criterion: "hdr",
                                criterion_name: "User-Agent",
                                converter: "str",
                                dns: true,
                                case: false,
                                operator: "",
                                pattern: response.log_line.http_user_agent,
                                error: null
                            }]
                        }]


                        self.or_lines = rules;
                        init_interface();
                        self.render_rule();
                    }
                }
            )
        } else {
            self.add_or();
        }
    }
})


$(function(){
    init_interface();
})