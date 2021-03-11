const name_choices = {
    'variable': [
        "users", "group", "memberof"
    ]
};


let auth_access_control_vue;

auth_access_control_vue = new Vue({
    el: '#auth_access_control_vue',
    delimiters: ['${', '}'],
    data: {
        or_lines: [],
        rule: ""
    },

    mounted: function(){
        if (object_id !== "None"){
            axios.get(auth_access_control_api_uri, {params: {object_id: object_id}})
                .then((response) => {
                    this.or_lines = response.data.res.rules;
                })
                .catch((error) => {
                    throw error
                })
        } else {
            this.add_or();
        }
    },

    watch: {
        or_lines() {
            this.change()
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
    
    methods: {
        change() {
            setTimeout(() => {
                for (or_index in this.or_lines){
                    for (and_index in this.or_lines[or_index].lines){
                        let id = `#variable_name_${or_index}_${and_index}`
                        $(id).tagsinput({
                            maxTags: 1,
                            freeInput: true
                        })
                    }
                }
            }, 100)
        },

        is_selected(type, line, value){
            if (line[type] === value)
                return "selected";
        },

        generate_id(){
            return Math.random().toString(36).substring(5);
        },

        render_and(index){
            if (index > 0)
                return '<label class="label label-primary">AND</label>';
        },

        get_or_index(or_id){
            for (let i in this.or_lines){
                if (this.or_lines[i].pk === or_id)
                    return i;
            }
        },

        check_acl(acl){
            PNotify.removeAll();

            if (!acl.variable_name)
                return 'variable';

            if (!acl.operator)
                return 'operator'

            if (!acl.value)
                return 'value'

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

        render_class_end_line(error){
            var classe = "and_line";
            if (error)
                classe += " and_line_error";

            return classe;
        },

        add_or(){
            let pk = this.generate_id();
            this.or_lines.push({
                pk: pk,
                lines: []
            });

            this.add_and(pk);
        },

        remove_or(or_id){
            let index = this.get_or_index(or_id);
            this.or_lines.splice(index, 1);
        },

        render_id(or_index, and_index){
            return `and_line_${or_index}_${and_index}`;
        },

        render_variable_id(or_index, and_index){
            return `variable_name_${or_index}_${and_index}`
        },

        reconstruct_rules(){
            var self = this;
            $('.condition_block').each(function(){
                var or_index = $(this).data('index');
                $(this).find('.and_line').each(function(){
                    var and_index = $(this).data('index');
                    var and_line = self.or_lines[or_index].lines[and_index];

                    let tr = $(`#and_line_${or_index}_${and_index}`);

                    and_line.variable_name = $(tr).find('.variable_name').val();
                    and_line.operator = $(tr).find('.operator').val();
                    and_line.value = $(tr).find('.value').val();

                    and_line.error = self.check_acl(and_line)

                    self.or_lines[or_index].lines[and_index] = and_line;
                })
            })
        },

        add_and(or_id){
            let index = this.get_or_index(or_id);

            this.reconstruct_rules();

            this.or_lines[index].lines.push({
                variable_name: "",
                operator: "",
                value: "",
                error: null
            });

            this.change()
        },

        remove_and(or_id, and_index){
            let index = this.get_or_index(or_id);
            this.or_lines[index].lines.splice(and_index, 1);
        },

        save_form(){
            this.reconstruct_rules();
            
            for (var or_line of this.or_lines){
                for (var and_line of or_line.lines){
                    if (this.check_acl(and_line) !== null){
                        return false;
                    }
                }
            }
            
            var txt = $('#save_form_btn').html();
            $('#save_form_btn').html('<i class="fa fa-spinner fa-spin"></i>');
            $('#save_form_btn').prop('disabled', 'disabled');

            var data = {
                or_lines: this.or_lines,
                name: $('#id_name').val().replace(/ /g, '_'),
                enabled: $('#id_enabled').is(':checked')
            };

            if (object_id !== "None"){
                // PUT
                axios.put(`${auth_access_control_api_uri}${object_id}`, data)
                    .then((response) => {
                        notify('success', gettext('Success'), response.data.message)
                        setTimeout(() => {
                            window.location.href = auth_access_control_list_uri
                        }, 1000)
                    })
                    .catch((error) => {
                        notify('error', gettext('Error'), error.response.data.error)
                    })
                    .then(() => {
                        $('#save_form_btn').html(txt)
                        $('#save_form_btn').prop('disabled', '')
                    })
            } else {
                axios.post(auth_access_control_api_uri, data)
                    .then((response) => {
                        notify('success', gettext('Success'), response.data.message)
                        setTimeout(() => {
                            window.location.href = auth_access_control_list_uri
                        }, 1000)
                    })
                    .catch((error) => {
                        notify('error', gettext('Error'), error.response.data.error)
                    })
                    .then(() => {
                        $('#save_form_btn').html(txt)
                        $('#save_form_btn').prop('disabled', '')
                    })
            }
        }
    },
})