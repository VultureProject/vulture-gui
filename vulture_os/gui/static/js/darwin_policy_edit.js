Vue.component('v-select', VueSelect.VueSelect)
Vue.component('vue-tags-input', vueTagsInput.vueTagsInput)
Vue.component('v-toggle-button', ToggleButton.ToggleButton)

let darwin_policy_edit_vue;

let available_filter_types = {}

$(function(){
  init_vue();
})

function init_vue(){

  // iterate over array given with HTML through jinja (see view)
  for (let tmp of darwin_filters){
    available_filter_types[tmp.id] = {
      label: tmp.name.toUpperCase() + " - " + tmp.longname,
      name: tmp.name,
      hint: tmp.description,
      is_launchable: tmp.is_launchable,
      is_internal: tmp.is_internal,
      can_be_buffered: tmp.can_be_buffered,
      custom_rsyslog_calls_possible: true
    }
  }

  darwin_policy_edit_vue = new Vue({
    el: "#darwin_policy_edit",
    delimiters: ['${', '}'],
    data: {
      policy: {
        name: "",
        description: "",
        filters: [],
      },

      tagRsyslog: "",
      enrichmentTagsRsyslog: "",
      filter: {
        filter_type: null,
        enabled: true,
        nb_thread: 5,
        log_level: "WARNING",
        threshold: 80,
        mmdarwin_enabled: false,
        mmdarwin_parameters: [],
        enrichment_tags: [],
        weight: 1.0,
        cache_size: 0,
        config: {
          redis_expire: 300,
          max_connections: 64000,
          yara_scan_type: "packet",
          yara_scan_max_size: 16384,
          max_memory_usage: 200,
          yara_policy_id: null,
          yara_policies_id: [],
          reputation_ctx_id: null,
          max_tokens: 75,
          timeout: 0,
          fastmode: true
        },
        continuous_analysis_enabled: false,
        buffering: {
          interval: 300,
          required_log_lines: 10
        }
      },

      buffer_outputs: [],
      filters_choices: [],
      log_level_choices: [
        {label: "Debug", id: "DEBUG"},
        {label: "Informational", id: "INFO"},
        {label: "Warning", id: "WARNING"},
        {label: "Error", id: "ERROR"},
      ],

      yara_scan_type_choices: [
        {label: "Packet", id: "packet"},
        {label: "Stream", id: "stream"}
      ],

      yara_rule_file_choices: [],

      yara_policies_list: [],
      hostlookup_reputation_choices: []
    },

    mounted() {
      let self = this

      for (let [filter_id, config] of Object.entries(available_filter_types)) {
        if (!config.is_internal)
          this.filters_choices.push({label: config.label, id: filter_id})
      }

      if (object_id){
        $.get(
          darwin_policy_api_uri + `/${object_id}`,
          null,

          function(response) {
            let data = response.data
            self.policy.name = data.name
            self.policy.description = data.description
            self.policy.buffer_outputs = []

            for (let filter of data.filters){
              filter_type = available_filter_types[filter.filter_type]
              if (filter_type) {
                if (filter_type.name === "content_inspection")
                  self.fetch_content_inspection_choices()
                else if (filter_type.name === "lkup")
                  self.fetch_reputation_ctx()
                else if (filter_type.name === "yara")
                  self.fetch_yara_rule_file()
              }

              let tmp_mmdarwin_parameters = []
              for (let tmp of filter.mmdarwin_parameters)
                tmp_mmdarwin_parameters.push({text: tmp})
              filter.mmdarwin_parameters = tmp_mmdarwin_parameters
              
              let tmp_enrichment_tags = []
              for (let tmp of filter.enrichment_tags)
                tmp_enrichment_tags.push({text: tmp})
              filter.enrichment_tags = tmp_enrichment_tags

              filter.continuous_analysis_enabled = (filter.buffering != null)
              self.policy.filters.push(filter)
            }
          }
        )
      }
    },

    watch: {
      "filter.filter_type"(filter_type_id) {
        let filter_type = available_filter_types[filter_type_id]
        if (filter_type) {
          if (filter_type.name === "content_inspection")
            this.fetch_content_inspection_choices()
          else if (filter_type.name === "lkup")
            this.fetch_reputation_ctx()
          else if (filter_type.name === "yara")
            this.fetch_yara_rule_file()

          if (!filter_type.is_launchable) {
            this.filter.enabled = false
          }
        }
      }
    },

    methods: {
      renderLabel(filter_type_id) {
        return (available_filter_types[filter_type_id]) ? available_filter_types[filter_type_id].label : ""
      },

      renderName(filter_type_id) {
        return (available_filter_types[filter_type_id]) ? available_filter_types[filter_type_id].name : ""
      },

      renderButtonColor(filter_type_id) {
        let filter_type = available_filter_types[filter_type_id]
        if(filter_type && filter_type.is_launchable){
          console.log("is launchable")
          return {checked: '#75C791', unchecked: '#BFCBD9'}
        }
        else {
          console.log("is not launchable")
          return {checked: '#E45050', unchecked: '#BFCBD9'}
        }
      },

      renderBoolean(val) {
        if (val)
          return "<i class='fa fa-check'></i>"
        return "<i class='fa fa-times'></i>"
      },

      renderLogLevel(val){
        let mapping = {
          "DEBUG": "label-primary",
          "INFO": "label-info",
          "WARNING": "label-warning",
          "ERROR": "label-danger"
        }

        return `<label class='label ${mapping[val]}'>${val}</label>`
      },

      renderCustomConfig(filter){
        let rsyslog_params = ""
        let continuous_analysis_enabled = ""
        let filter_type_name = (available_filter_types[filter.filter_type]) ? available_filter_types[filter.filter_type].name : ""

        if (filter.mmdarwin_enabled){
          let tmp = []

          for (let tag of filter.mmdarwin_parameters)
            tmp.push(`<label class='label label-primary'>${tag.text}</label>`)

          rsyslog_params += `<p><b>${gettext("Overriden Rsyslog inputs")}:</b> ${tmp.join(' ')}</p>`
        }
        
        if (filter.enrichment_tags.length > 0){
          let tmp = []

          for (let tag of filter.enrichment_tags)
            tmp.push(`<label class='label label-primary'>${tag.text}</label>`)

          rsyslog_params += `<p><b>${gettext("Additional Rsyslog enrichment tags")}:</b> ${tmp.join(' ')}</p>`
        }
        
        if (filter.continuous_analysis_enabled){
          continuous_analysis_enabled = `<b>${gettext('Continuous Analysis')}:</b><ul><li><b>${gettext("Analysis interval")}:</b> ${filter.buffering.interval}</li>`
          continuous_analysis_enabled += `<li><b>${gettext("Analysis min entries")}:</b> ${filter.buffering.required_log_lines}</li></ul>`
        }

        let customConfig = ""
        switch(filter_type_name){
          case "conn":
            customConfig = `
              <p><b>${gettext("Redis Expire")}:</b> ${filter.config.redis_expire}</p>
            `
            break

          case "content_inspection":
            let label_yara_rule_file = ""
            for (let file of this.yara_rule_file_choices){
              if (file.id === filter.config.yara_policy_id)
                label_yara_rule_file = file.label
            }

            customConfig = `
              <p><b>${gettext("Max connexions")}:</b> ${filter.config.max_connections}</p>
              <p><b>${gettext("Yara Scan Type")}:</b> ${filter.config.yara_scan_type}</p>
              <p><b>${gettext("Yara Scan Max Size")}:</b> ${filter.config.yara_scan_max_size}</p>
              <p><b>${gettext("Max Memory usage")}:</b> ${filter.config.max_memory_usage}</p>
              <p><b>${gettext("Yara Rule File")}:</b> ${label_yara_rule_file}</p>
            `
            break

          case "dgad":
            customConfig = `
              <p><b>${gettext('Max Tokens')}:</b> ${filter.config.max_tokens}</p>
            `
            break

          case "lkup":
            label_hostlookup_rule_file = ""
            for (let tmp of this.hostlookup_reputation_choices) {
              if (filter.config.reputation_ctx_id === tmp.id)
                label_hostlookup_rule_file = tmp.label
            }
            customConfig = `
              <p><b>${gettext("Database")}:</b> ${label_hostlookup_rule_file}</p>
            `
            break

          case "yara":
            let rule_file_list = []
            for (let id of filter.config.yara_policies_id){
              for (let tmp of this.yara_policies_list){
                if (id === tmp.id)
                  rule_file_list.push(`<label class='label label-primary'>${tmp.label}</label>`)
              }
            }

            customConfig = `
              <p><b>${gettext("Fast Mode")}:</b> ${filter.config.fastmode}</p>
              <p><b>${gettext("Timeout")}:</b> ${filter.config.timeout}</p>
              <p><b>${gettext("Rule file list")}:</b> ${rule_file_list.join('&nbsp;')}</p>
            `
            break
        }

        return `
          ${rsyslog_params}
          ${continuous_analysis_enabled}
          ${customConfig}
        `
      },

      fetch_content_inspection_choices() {
        let self = this

        $.get(
          darwin_inspection_policies_uri,
          null,

          function(response) {
            self.yara_rule_file_choices = []
            for (let tmp of response.data){
              self.yara_rule_file_choices.push({
                label: tmp.name,
                id: tmp.id
              })
            }
          }
        ).fail(function(response) {
          let error = response.responseJSON.error
          notify('error', gettext('Error'), error)
        })
      },

      fetch_reputation_ctx() {
        let self = this

        $.get(
          application_reputation_ctx_uri,
          null,

          function(response) {
            self.hostlookup_reputation_choices = []
            for (let tmp of response.data){
              if ($.inArray(tmp.db_type, ["ipv4_netset", "ipv6_netset", "domain", "lookup"]) > -1){
                self.hostlookup_reputation_choices.push({
                  label: tmp.name,
                  id: tmp.id
                })
              }
            }
          }
        ).fail(function(response) {
          let error = response.responseJSON.error
          notify('error', gettext('Error'), error)
        })
      },

      fetch_yara_rule_file() {
        let self = this

        $.get(
          darwin_inspection_policies_uri,
          null,

          function(response) {
            self.yara_policies_list = []
            for (let tmp of response.data){
              self.yara_policies_list.push({
                label: tmp.name,
                id: tmp.id
              })
            }
          }
        )
      },

      custom_rsyslog_calls(filter_type_id) {
        return (available_filter_types[filter_type_id]) ? available_filter_types[filter_type_id].custom_rsyslog_calls_possible : false
      },
      
      can_be_buffered(filter_type_id) {
        return (available_filter_types[filter_type_id]) ? available_filter_types[filter_type_id].can_be_buffered : false
      },
      
      is_internal(filter_type_id) {
        return (available_filter_types[filter_type_id]) ? available_filter_types[filter_type_id].is_internal : false
      },

      is_launchable(filter_type_id) {
        return (available_filter_types[filter_type_id]) ? available_filter_types[filter_type_id].is_launchable : false
      },
      
      hint(filter_type_id){
        return (available_filter_types[filter_type_id]) ? available_filter_types[filter_type_id].hint : ""
      },

      editFilter(index){
        this.filter = this.policy.filters[index]
        this.policy.filters.splice(index, 1)
      },

      addFilter() {
        if (!this.filter.filter_type)
          return

        let data = {}
        Object.assign(data, this.filter)

        this.policy.filters.push(data)

        this.filter = {
          filter_type: null,
          enabled: true,
          nb_thread: 5,
          log_level: "WARNING",
          threshold: 80,
          mmdarwin_enabled: false,
          mmdarwin_parameters: [],
          enrichment_tags: [],
          weight: 1.0,
          cache_size: 0,
          config: {
            redis_expire: 300,
            max_connections: 64000,
            yara_scan_type: "packet",
            yara_scan_max_size: 16384,
            max_memory_usage: 200,
            yara_policy_id: null,
            yara_policies_id: [],
            reputation_ctx_id: null,
            max_tokens: 75,
            timeout: 0,
            fastmode: true
          },
          continuous_analysis_enabled: false,
          buffering: {
            interval: 300,
            required_log_lines: 10
          }
        }
      },

      removeFilter(index) {
        this.policy.filters.splice(index, 1)
      },

      savePolicy() {
        let self = this
        let filters = []

        for (let tmp_filter of this.policy.filters){
          let config = {}
          let buffering = null
          let mmdarwin_parameters = []
          let enrichment_tags = []
          filter_type_name = (available_filter_types[tmp_filter.filter_type]) ? available_filter_types[tmp_filter.filter_type].name : ""

          switch(filter_type_name){
            case "conn":
              config.redis_expire = parseInt(tmp_filter.config.redis_expire, 10)
              break

            case "content_inspection":
              config.max_connections = parseInt(tmp_filter.config.max_connections, 10)
              config.yara_scan_type = tmp_filter.config.yara_scan_type
              config.yara_scan_max_size = parseInt(tmp_filter.config.yara_scan_max_size, 10)
              config.max_memory_usage = parseInt(tmp_filter.config.max_memory_usage, 10)
              config.yara_policy_id = parseInt(tmp_filter.config.yara_policy_id, 10)
              break

              case "dgad":
                config.max_tokens = parseInt(tmp_filter.config.max_tokens, 10)
                break

              case "lkup":
                config.reputation_ctx_id = parseInt(tmp_filter.config.reputation_ctx_id, 10)
                break

              case "yara":
                config.fastmode = tmp_filter.config.fastmode
                config.timeout = parseInt(tmp_filter.config.timeout, 10)
                config.yara_policies_id = tmp_filter.config.yara_policies_id
                break
          }

          for (let tmp of tmp_filter.mmdarwin_parameters)
            mmdarwin_parameters.push(tmp.text)
          
          for (let tmp of tmp_filter.enrichment_tags)
            enrichment_tags.push(tmp.text)

          if (tmp_filter.continuous_analysis_enabled) {
            buffering = {}
            buffering.interval = tmp_filter.buffering.interval
            buffering.required_log_lines = tmp_filter.buffering.required_log_lines
          }

          let tmp = {
            filter_type: tmp_filter.filter_type,
            enabled: tmp_filter.enabled,
            threshold: parseInt(tmp_filter.threshold, 10),
            log_level: tmp_filter.log_level,
            nb_thread: parseInt(tmp_filter.nb_thread, 10),
            weight: parseFloat(tmp_filter.weight),
            cache_size: parseInt(tmp_filter.cache_size, 10),
            mmdarwin_enabled: tmp_filter.mmdarwin_enabled,
            mmdarwin_parameters: mmdarwin_parameters,
            enrichment_tags: enrichment_tags,
            config: config,
            buffering: buffering
          }

          filters.push(tmp)
        }

        if (filters.length === 0){
          notify('error', gettext('Error'), gettext("Please add at least one filter"))
          return
        }

        let data = {
          name: this.policy.name,
          description: this.policy.description,
          filters: JSON.stringify(filters)
        }

        if (!object_id){
          $.post(
            darwin_policy_api_uri,
            data,

            function(response) {
              notify('success', gettext("Success"), gettext("Policy successfully created"))

              setTimeout(function(){
                window.location.href = darwin_policy_list_uri
              }, 1000)
            }
          ).fail(function(response) {
            let error = response.responseJSON.error
            notify('error', gettext('Error'), error)
          })
        } else {
          $.ajax({
            url: darwin_policy_api_uri + `/${object_id}`,
            type: "PUT",
            data: JSON.stringify(data),
            contentType: "application/json",
            success: function(response){
              notify('success', gettext("Success"), gettext("Policy successfully updated"))

              setTimeout(function(){
                window.location.href = darwin_policy_list_uri
              }, 1000)
            },

            error: function (xhr, ajaxOptions, thrownError) {
              notify('error', gettext('Error'), xhr.responseJSON.error)
            }
          })
        }
      }
    }
  })
}