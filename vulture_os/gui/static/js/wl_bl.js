let wlbl_vue = new Vue({
    el: "#wlbl_tab",
    delimiters: ['${', '}'],
    data: {
        log_line: null,
        or_lines: [],
        rule: "",
        wl_bl_columns: ['http_method', 'http_get_params', 'http_request', 'http_version', 'http_path', 'captured_request_cookie', 'status_code'],
        available_columns: [],
        selected_app: null,
        resume_rule: null
    },

    watch: {

        log_line(line){
            var self = this;
            var filters = [];
            var rules = {condition: 'AND', rules: []};

            $.each(line, function(k, v){
                if ($.inArray(k, ['_id', 'time', 'timestamp_app', 'unix_timestamp', 'date_time']) === -1){
                    var type = mapping[k];

                    if (type !== "dict"){
                        if (type === "float")
                            type = "double"

                        var filter = {
                            id: k,
                            label: k,
                            type: type,
                            default_value: v,
                            size: 60
                        }

                        if (type === "double")
                            filter.input = "number"

                        filters.push(filter)
                        
                        if ($.inArray(k, self.wl_bl_columns) > -1 && v !== ""){
                            var tmp = {
                                id: k,
                                field: k,
                                type: type,
                                value: v
                            }

                            if (type === "double")
                                tmp.type = "number"

                            rules.rules.push(tmp)
                        }
                    }

                }
            })

            try{
                $('#query-builder-waf').queryBuilder('destroy');
            } catch(err){}

            $('#query-builder-waf').queryBuilder({
                sort_filters: true,
                allow_empty: true,
                filters: filters,
                default_group_flags: {
                    no_add_group: true
                },
                // taken from https://querybuilder.js.org/api/defaults.js.html#line-97, minus in/nin
                operators: [
                    { type: 'equal', nb_inputs: 1, multiple: false, apply_to: ['string', 'number', 'datetime', 'boolean'] },
                    { type: 'not_equal', nb_inputs: 1, multiple: false, apply_to: ['string', 'number', 'datetime', 'boolean'] },
                    { type: 'less', nb_inputs: 1, multiple: false, apply_to: ['number', 'datetime'] },
                    { type: 'less_or_equal', nb_inputs: 1, multiple: false, apply_to: ['number', 'datetime'] },
                    { type: 'greater', nb_inputs: 1, multiple: false, apply_to: ['number', 'datetime'] },
                    { type: 'greater_or_equal', nb_inputs: 1, multiple: false, apply_to: ['number', 'datetime'] },
                    { type: 'between', nb_inputs: 2, multiple: false, apply_to: ['number', 'datetime'] },
                    { type: 'not_between', nb_inputs: 2, multiple: false, apply_to: ['number', 'datetime'] },
                    { type: 'begins_with', nb_inputs: 1, multiple: false, apply_to: ['string'] },
                    { type: 'not_begins_with', nb_inputs: 1, multiple: false, apply_to: ['string'] },
                    { type: 'contains', nb_inputs: 1, multiple: false, apply_to: ['string'] },
                    { type: 'not_contains', nb_inputs: 1, multiple: false, apply_to: ['string'] },
                    { type: 'ends_with', nb_inputs: 1, multiple: false, apply_to: ['string'] },
                    { type: 'not_ends_with', nb_inputs: 1, multiple: false, apply_to: ['string'] },
                    { type: 'is_empty', nb_inputs: 0, multiple: false, apply_to: ['string'] },
                    { type: 'is_not_empty', nb_inputs: 0, multiple: false, apply_to: ['string'] },
                    { type: 'is_null', nb_inputs: 0, multiple: false, apply_to: ['string', 'number', 'datetime', 'boolean'] },
                    { type: 'is_not_null', nb_inputs: 0, multiple: false, apply_to: ['string', 'number', 'datetime', 'boolean'] }
                ],
                plugins: [
                    'invert',
                    'sortable'
                ]
            })

            $('#query-builder-waf').queryBuilder('setRules', rules);
            self.event_builder();
            self.rules_preview();
        }
    },

    methods: {
        event_builder(){
            var self = this;

            // Refresh SQL at every change on queryBuilder
            // Event 'rulesChanged' doesn't work

            var events = [
                'afterAddGroup.queryBuilder', 'afterUpdateGroupCondition.queryBuilder', 'afterDeleteGroup.queryBuilder', 
                'afterAddRule.queryBuilder', 'afterUpdateRuleFilter.queryBuilder', 'afterUpdateRuleOperator.queryBuilder', 
                'afterUpdateRuleValue.queryBuilder', 'afterDeleteRule.queryBuilder', 'afterReset.queryBuilder', 'afterSetRules.queryBuilder'
            ];

            for (var event of events){
                $('#query-builder-waf').on(event, function(){
                    self.rules_preview();
                })
            }
        },

        rules_preview(){
            // Show preview of queryBuilder rules. SQL Syntax
            var rules_sql = $('#query-builder-waf').queryBuilder('getSQL', false);
            if (rules_sql)
                this.resume_rule = rules_sql.sql;
        },

        save_rules(){
            var self = this;
            var rules_name = prompt("Please a name for these rules", "");

            $.post(
                waf_rules_uri,
                {
                    rules: JSON.stringify($('#query-builder-waf').queryBuilder('getMongo')),
                    frontend_name: self.selected_app,
                    name: rules_name
                },

                function(response){
                    if (!response.status){
                        notify('error', gettext('Error'), response.error);
                    } else {
                        notify('success', gettext('Success'), gettext('Rules applied'));

                        setTimeout(function(){
                            $('.btn-close-wlbl_tab').click();
                        }, 300);

                    }
                }
            )
        }
    }
})
