Vue.component('v-select', VueSelect.VueSelect)
Vue.component('vue-tags-input', vueTagsInput.vueTagsInput)
Vue.component('v-toggle-button', ToggleButton.ToggleButton)

function makeid(length) {
  var result = '';
  var characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  var charactersLength = characters.length;
  for ( var i = 0; i < length; i++ ) {
    result += characters.charAt(Math.floor(Math.random() * charactersLength));
  }
  return result;
}

let ldap_view = new Vue({
  el: "#ldap_view",
  delimiters: ['${', '}'],
  data: {
    ldap_repository: null,
    group_table: null,
    group_keys: [],
    user_keys: [],
    groups: [],
    users: []
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
    groups() {
      this.initGroupTable()
    }
  },

  methods: {
    editGroup(dn) {
      console.log(dn)
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
            if (this.group_table.fnIsOpen(nRow)){
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
    getGroups(){
      axios.get(ldap_view_api_uri, {params: {'object_type': 'groups'}})
        .then((response) => {
          this.groups = response.data.groups
        })
    }
  }
})