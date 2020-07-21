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
        log_level: "DEBUG",
        threshold: 80,
        nb_thread: 5,
        weight: 1.0,
        cache_size: 0,
        is_configured: false,
        mmdarwin_enabled: false,
        mmdarwin_parameters: [],
        config: {
          redis_expire: 300,
          max_connections: 64000,
          yaraScanType: "packet",
          yara_scan_max_size: 16384,
          max_memory_usage: 200,
          yara_rule_file: null,
          database: null,
          timeout: 0,
          token_map_path: null,
          model_path: null
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
      hostlookup_database_choices: []
    },

    mounted() {
      let self = this

      for (let [filter_name, config] of Object.entries(available_filters))
        this.filters_choices.push({label: config.label, id: filter_name})

      if (object_id){
        // FIXME: Fetch policy configuration
        $.get(
          darwin_policy_api_uri + `/${object_id}`,
          null,

          function(response) {
            let data = response.data
            self.policy.name = data.name
            self.policy.description = data.description

            for (let filter of data.filters){
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

        this.filter.is_configured = true
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
          "DANGER": "label-danger"
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
              if (file.id === filter.config.yara_rule_file)
                label_yara_rule_file = file.label
            }

            customConfig = `
              <p><b>${gettext("Max connexions")}:</b> ${filter.config.max_connections}</p>
              <p><b>${gettext("Yara Scan Type")}:</b> ${filter.config.yaraScanType}</p>
              <p><b>${gettext("Yara Scan Max Size")}:</b> ${filter.config.yara_scan_max_size}</p>
              <p><b>${gettext("Max Memory usage")}:</b> ${filter.config.max_memory_usage}</p>
              <p><b>${gettext("Yara Rule File")}:</b> ${label_yara_rule_file}</p>
            `
            break

          case "dga":
            customConfig = `
              <p><b>${gettext('Model')}:</b> ${filter.config.model_path}</p>
              <p><b>${gettext('Token')}:</b> ${filter.config.token_map_path}</p>
            `
            break
          
          case "hostlookup":
            customConfig = `
              <p><b>${gettext("Database")}:</b> ${filter.config.database}</p>
            `
            break
          
          case "yara":
            customConfig = `
              <p><b>${gettext("Fast Mode")}:</b> ${filter.config.fast_mode}</p>
              <p><b>${gettext("Timeout")}:</b> ${filter.config.timeout}</p>
              <p><b>${gettext("Rule file list")}:</b> ${filter.config.yara_rule_file_list}</p>
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
        )
      },

      fetch_reputation_ctx() {
        let self = this

        $.get(
          application_reputation_ctx_uri,
          null,

          function(response) {
            self.hostlookup_database_choices = []
            for (let tmp of response.data){
              if ($.inArray(tmp, [ "ipv4_netset", "ipv6_netset", "domain", "lookup"]) > -1){
                self.hostlookup_database_choices.push({
                  label: tmp.name,
                  id: tmp.id
                })
              }
            }
          }
        )
      },

      fetch_dga_models() {
        let self = this

        $.get(
          darwin_filter_api_uri + "dga/",
          null,

          function(response){
            self.dga_model_choices = []
            self.token_map_path = []

            for (let tmp of response.data.models){
              self.dga_model_choices.push({
                label: tmp,
                id: tmp
              })
            }

            for (let tmp of response.data.tokens){
              self.dga_token_choices.push({
                label: tmp,
                id: tmp
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
        this.selected_filter = this.filter.name
        this.policy.filters.splice(index, 1)
        this.filter.is_configured = true
      },

      addFilter() {
        if (this.filter.name === "dga"){
          if (!this.filter.config.model_path || !this.filter.config.token_map_path){
            notify('error', gettext("Error"), gettext("Please fill all required field"))
            return
          }
        }

        let data = {}
        Object.assign(data, this.filter)

        this.policy.filters.push(data)

        this.filter = {
          name: "",
          enabled: true,
          log_level: "DEBUG",
          threshold: 80,
          nb_thread: 5,
          weight: 1.0,
          cache_size: 0,
          is_configured: false,
          mmdarwin_enabled: false,
          mmdarwin_parameters: [],
          config: {
            redis_expire: 300,
            max_connections: 64000,
            yaraScanType: "packet",
            yara_scan_max_size: 16384,
            max_memory_usage: 200,
            yara_rule_file: null,
            database: null,
            timeout: 0,
            token_map_path: null,
            model_path: null
          }
        }
        this.selected_filter = null
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
              config.redis_expire = tmp_filter.config.redis_expire
              break
            
            case "content_inspection":
              config.max_connections = tmp_filter.config.max_connections
              config.yaraScanType = tmp_filter.config.yaraScanType
              config.yara_scan_max_size = tmp_filter.config.yara_scan_max_size
              config.max_memory_usage = tmp_filter.config.max_memory_usage
              config.yara_rule_file = tmp_filter.config.yara_rule_file
              break
            
              case "dga":
                config.model_path = tmp_filter.config.model_path
                config.token_map_path = tmp_filter.config.token_map_path
                break
              
              case "hostlookup":
                config.database = tmp_filter.config.database
                break
              
              case "yara":
                config.fast_mode = tmp_filter.config.fast_mode
                config.timeout = tmp_filter.config.timeout
                config.yara_rule_file_list = tmp_filter.config.yara_rule_file_list
                break
          }

          let mmdarwin_parameters = []
          for (let tmp of tmp_filter.mmdarwin_parameters)
            mmdarwin_parameters.push(tmp.text)

          let tmp = {
            name: tmp_filter.name,
            enabled: tmp_filter.enabled,
            threshold: tmp_filter.threshold,
            log_level: tmp_filter.log_level,
            nb_thread: tmp_filter.nb_thread,
            weight: tmp_filter.weight,
            cache_size: tmp_filter.cache_size,
            mmdarwin_enabled: tmp_filter.mmdarwin_enabled,
            mmdarwin_parameters: mmdarwin_parameters,
            config: config
          }

          filters.push(tmp)
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
          )
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
              notify('error', gettext('Error'), thrownError)
            }
          })
        }
      }
    }
  })
}