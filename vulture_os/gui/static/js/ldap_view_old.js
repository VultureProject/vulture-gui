Vue.component('v-select', VueSelect.VueSelect)
Vue.component('vue-tags-input', vueTagsInput.vueTagsInput)
Vue.component('v-toggle-button', ToggleButton.ToggleButton)

function makeid(length) {
  var result = '';
  var characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  var charactersLength = characters.length;
  for (var i = 0; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * charactersLength));
  }
  return result;
}

let ldap_view = new Vue({
  el: "#ldap_view",
  delimiters: ['${', '}'],
  data: {
    ldap_repository: null,
    form_group: {
      group_name: "",
      members: ""
    },
    group_table: null,
    group_keys: [],
    user_keys: [],
    groups: [],
    members: [],
    autocomplete_members: []
  },

  mounted() {
    axios.get(ldap_api_uri)
      .then((response) => {
        this.ldap_repository = response.data.data
        this.user_keys = response.data.available_user_keys
        this.group_keys = response.data.available_group_keys
        this.getGroups()
      })
  },

  watch: {
    "form_group.members": "autocomplete_users",
    groups() {
      this.initGroupTable()
    }
  },

  methods: {
    autocomplete_users(elem) {
      this.autocomplete_members = []
      if (this.form_group.members.length < 2) return;
      axios.get(ldap_view_api_uri, { params: { object_type: "users", search: elem } })
        .then((response) => {
          let data = []
          for (let tmp of response.data.users)
            data.push({ text: tmp })

          this.autocomplete_members = data
        })
      return []
    },
    memberTagsChanged(newTags) {
      this.members = newTags
      this.autocomplete_members = []
    },

    addGroup() {
      let members = []
      for (let m of this.members)
        members.push(m.text)

      if (members.length === 0) {
        notify('error', gettext('Error'), gettext("At least one member is required"))
        return
      }

      let data = {
        object_type: "group",
        group_name: this.form_group.group_name,
        member: members
      }

      axios.post(ldap_view_api_uri, data)
        .then((response) => {
          if (response.status === 201) {
            this.memberTagsChanged([])
            this.form_group = {
              group_name: "",
              members: ""
            }
            $('#modal-add-group').modal('hide')
            notify('success', gettext("Success"), gettext("Group successfully created"))
            this.getGroups()
          }
        })
        .catch((error) => {
          console.error(error.response.data)
        })
    },

    initGroupTable() {
      let columns = [{
        sTitle: "dn",
        name: "dn",
        aTargets: [0],
        mData: 'dn'
      }, {
        sTitle: gettext('Nb users'),
        name: 'members',
        aTargets: [1],
        mData: 'member',
        sWidth: "10%",
        mRender: (data, type, row) => {
          return data.length
        }
      }]

      this.group_table = $('#groups_list').dataTable({
        order: [[0, 'desc']],
        iDisplayLength: 10,
        aoColumns: columns,
        aaData: this.groups,
        fnCreatedRow: (nRow, aData, iDataIndex) => {
          $(nRow).on('click', () => {
            if (this.group_table.fnIsOpen(nRow)) {
              this.group_table.fnClose(nRow)
              return
            }

            let comp = new UserListComponent({
              propsData: {
                group_keys: this.group_keys,
                user_keys: this.user_keys,
                group: aData,
                id: makeid(8)
              }
            }).$mount()
            this.group_table.fnOpen(nRow, comp.$el, 'details')
          })
        }
      })
    },
    getGroups() {
      if (this.group_table) {
        this.group_table.fnDestroy()
        $('#groups_list').empty()
      }

      axios.get(ldap_view_api_uri, { params: { 'object_type': 'groups' } })
        .then((response) => {
          this.groups = response.data.groups
        })
    }
  }
})