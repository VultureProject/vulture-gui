Vue.component('v-select', VueSelect.VueSelect)

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
        available_operators: []
    },

    mounted: function(){
        for (let [_, operator] of Object.entries(operator_choices)) {
            this.available_operators.push({id: operator[0], label: operator[1]})
        }

        if (object_id !== "None"){
            axios.get(auth_access_control_api_uri, {params: {object_id: object_id}})
                .then((response) => {
                    this.or_lines = response.data.res.rules;
                    this.refresh_errors();
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
            this.refresh_errors()
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
            errors = {}

            if (!acl.variable_name)
                errors['variable_name'] = 'variable name is mandatory'

            if (!acl.operator)
                errors['operator'] = 'operator is mandatory'
            // if operator is not in the list of valid choices
            else if(Array.from(auth_access_control_vue.available_operators, x => x.id).indexOf(acl.operator) == -1)
                errors['operator'] =  'operator is not valid'

            if (acl.operator !== "exists" && acl.operator !== "not_exists" && !acl.value)
                errors['value'] =  'value is mandatory'

            return errors;
        },

        render_errors(errors, input){
            // Generic error
            if (!input){
                return "<i class='fas fa-exclamation-triangle fa-2x'></i>";
            }
            // Field error
            else if (errors !== undefined && Object.keys(errors).length !== 0 && input in errors){
                return "<i class='fas fa-exclamation-triangle'></i>&nbsp;&nbsp;&nbsp;" + gettext(errors[input]);
            }
            return "";
        },

        render_class_end_line(errors){
            var classes = "and_line";
            if (errors !== undefined && Object.keys(errors).length !== 0)
                classes += " and_line_error";

            return classes;
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

        refresh_errors(){
            var self = this;
            for(or_line of this.or_lines) {
                for(and_line of or_line.lines) {
                    and_line.errors = self.check_acl(and_line)
                }
            }
        },

        add_and(or_id){
            let index = this.get_or_index(or_id);

            this.refresh_errors();

            this.or_lines[index].lines.push({
                variable_name: "",
                operator: "",
                value: "",
                errors: {}
            });
        },

        remove_and(or_id, and_index){
            let index = this.get_or_index(or_id);
            this.or_lines[index].lines.splice(and_index, 1);
        },

        save_form(){
            this.refresh_errors();

            for (var or_line of this.or_lines){
                for (var and_line of or_line.lines){
                    if (and_line.errors !== undefined && Object.keys(and_line.errors).length !== 0){
                        return false;
                    }
                }
            }

            // lines validated, Remove 'errors' value from dict after making sure we don't have any
            for (var or_line of this.or_lines){
                for (var and_line of or_line.lines){
                    delete(and_line.errors)
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