Vue.component('v-select', VueSelect.VueSelect)
Vue.component('vue-tags-input', vueTagsInput.vueTagsInput)
Vue.component('v-toggle-button', ToggleButton.ToggleButton)

let darwin_policy_edit_vue;

let available_filters = {
  anomaly: {
    label: gettext("Anomaly"),
    hint: gettext("The anomaly filter detects abnormal variations in network traffic")
  },
  connection: {
    label: gettext("Connection"),
    hint: gettext("The connection filter detects opening connections between assets"),
    custom_rsyslog_calls_possible: true
  },
  content_inspection: {
    label: gettext("Content Inspection"),
    hint: gettext("The content inspection filter detects patterns in network packets"),
    custom_rsyslog_calls_possible: true
  },
  dga: {
    label: gettext("DGA"), 
    hint: gettext("The DGA filter detects the Domain Generation Algorithms (DGAs)"),
    custom_rsyslog_calls_possible: true
  },
  hostlookup: {
    label: gettext("Host Lookup"),
    hint: gettext("The host lookup filter searches for matches in a list for matching hostnames"),
    custom_rsyslog_calls_possible: true
  },
  tanomaly: {
    label: gettext("TAnomaly"),
    hint: gettext("The tanomaly filter is a threaded anomaly filter, detecting variations continuously on network traffic"),
    custom_rsyslog_calls_possible: true
  },
  yara: {
    label: gettext("Yara"),
    hint: gettext("The Yara filter runs the yara engine on arbitrary data loaded in memory"),
    custom_rsyslog_calls_possible: true
  },
  sofa: {
    label: gettext("Sofa"),
    hint: gettext(""),
    custom_rsyslog_calls_possible: true
  }
}

$(function(){
  init_vue()
})

function init_vue(){
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
      filter: {
        name: "",
        enabled: true,
        log_level: "WARNING",
        threshold: 80,
        nb_thread: 5,
        weight: 1.0,
        cache_size: 0,
        mmdarwin_enabled: false,
        mmdarwin_parameters: [],
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
          fastmode: true,
          token_map: null,
          model: null
        }
      },

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

      dga_model_choices: [],
      dga_token_choices: [],
      yara_policies_list: [],
      hostlookup_reputation_choices: []
    },

    mounted() {
      let self = this

      for (let [filter_name, config] of Object.entries(available_filters))
        this.filters_choices.push({label: config.label, id: filter_name})

      if (object_id){
        $.get(
          darwin_policy_api_uri + `/${object_id}`,
          null,

          function(response) {
            let data = response.data
            self.policy.name = data.name
            self.policy.description = data.description

            for (let filter of data.filters){
              if (filter.name === "content_inspection")
                self.fetch_content_inspection_choices()
              else if (filter.name === "hostlookup")
                self.fetch_reputation_ctx()
              else if (filter.name === "dga")
                self.fetch_dga_models()
              else if (filter.name === "yara")
                self.fetch_yara_rule_file()

              let tmp_mmdarwin_parameters = []
              for (let tmp of filter.mmdarwin_parameters)
                tmp_mmdarwin_parameters.push({text: tmp})
              
              filter.mmdarwin_parameters = tmp_mmdarwin_parameters
              self.policy.filters.push(filter)
            }
          }
        )
      }
    },

    watch: {
      "filter.name"(val) {
        if (val === "content_inspection")
          this.fetch_content_inspection_choices()
        else if (val === "hostlookup")
          this.fetch_reputation_ctx()
        else if (val === "dga")
          this.fetch_dga_models()
        else if (val === "yara")
          this.fetch_yara_rule_file()
      }
    },
    
    methods: {
      renderName(val) {
        return available_filters[val].label
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
        if (filter.name === "anomaly")
          return ""

        let rsyslog_params = `<p><b>${gettext('Custom Rsyslog')}:</b> ${this.renderBoolean(filter.mmdarwin_enabled)}</p>`

        if (filter.mmdarwin_enabled){
          let tmp = []
          for (let tag of filter.mmdarwin_parameters)
            tmp.push(`<label class='label label-primary'>${tag.text}</label>`)

          rsyslog_params += `<p><b>${gettext("Rsyslog Params")}:</b> ${tmp.join(' ')}</p>`
        }

        let customConfig = ""
        switch(filter.name){
          case "connection":
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

          case "dga":
            customConfig = `
              <p><b>${gettext('Model')}:</b> ${filter.config.model}</p>
              <p><b>${gettext('Token')}:</b> ${filter.config.token_map}</p>
              <p><b>${gettext('Max Tokens')}:</b> ${filter.config.max_tokens}</p>
            `
            break
          
          case "hostlookup":
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

      fetch_dga_models() {
        let self = this

        $.get(
          darwin_filter_api_uri + "dga/",
          null,

          function(response){
            self.dga_model_choices = []
            self.dga_token_choices = []

            for (let tmp of response.data.models){
              self.dga_model_choices.push({
                label: tmp,
                id: tmp
              })
            }

            for (let tmp of response.data.token_maps){
              self.dga_token_choices.push({
                label: tmp,
                id: tmp
              })
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

      custom_rsyslog_calls(val) {
        return available_filters[val].custom_rsyslog_calls_possible
      },

      hint(val){
        return available_filters[val].hint
      },

      editFilter(index){
        this.filter = this.policy.filters[index]
        this.policy.filters.splice(index, 1)
      },

      addFilter() {
        if (!this.filter.name)
          return

        let data = {}
        Object.assign(data, this.filter)

        this.policy.filters.push(data)

        this.filter = {
          name: "",
          enabled: true,
          log_level: "WARNING",
          threshold: 80,
          nb_thread: 5,
          weight: 1.0,
          cache_size: 0,
          mmdarwin_enabled: false,
          mmdarwin_parameters: [],
          config: {
            redis_expire: 300,
            max_connections: 64000,
            yara_scan_type: "packet",
            yara_scan_max_size: 16384,
            max_memory_usage: 200,
            yara_policy_id: null,
            yara_policies_id: null,
            reputation_ctx_id: null,
            fastmode: true,
            timeout: 0,
            max_tokens: 75,
            token_map: null,
            model: null
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

          switch(tmp_filter.name){
            case "connection":
              config.redis_expire = parseInt(tmp_filter.config.redis_expire, 10)
              break
            
            case "content_inspection":
              config.max_connections = parseInt(tmp_filter.config.max_connections, 10)
              config.yara_scan_type = tmp_filter.config.yara_scan_type
              config.yara_scan_max_size = parseInt(tmp_filter.config.yara_scan_max_size, 10)
              config.max_memory_usage = parseInt(tmp_filter.config.max_memory_usage, 10)
              config.yara_policy_id = parseInt(tmp_filter.config.yara_policy_id, 10)
              break
            
              case "dga":
                config.model = tmp_filter.config.model
                config.token_map = tmp_filter.config.token_map
                config.max_tokens = parseInt(tmp_filter.config.max_tokens, 10)
                break
              
              case "hostlookup":
                config.reputation_ctx_id = parseInt(tmp_filter.config.reputation_ctx_id, 10)
                break
              
              case "yara":
                config.fastmode = tmp_filter.config.fastmode
                config.timeout = parseInt(tmp_filter.config.timeout, 10)
                config.yara_policies_id = tmp_filter.config.yara_policies_id
                break
          }

          let mmdarwin_parameters = []
          for (let tmp of tmp_filter.mmdarwin_parameters)
            mmdarwin_parameters.push(tmp.text)

          let tmp = {
            name: tmp_filter.name,
            enabled: tmp_filter.enabled,
            threshold: parseInt(tmp_filter.threshold, 10),
            log_level: tmp_filter.log_level,
            nb_thread: parseInt(tmp_filter.nb_thread, 10),
            weight: parseFloat(tmp_filter.weight),
            cache_size: parseInt(tmp_filter.cache_size, 10),
            mmdarwin_enabled: tmp_filter.mmdarwin_enabled,
            mmdarwin_parameters: mmdarwin_parameters,
            config: config
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