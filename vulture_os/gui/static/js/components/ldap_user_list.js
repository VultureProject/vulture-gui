let users_list_template = `
<div class="panel panel-bordered panel-dark">
  <div class="panel-heading">
    <div class="panel-control">
      <button class="btn" v-if="!users">
        <i class="fa fa-spinner fa-spin"></i>
      </button>
      <a class="btn btn-flat btn-default" href="#" @click="addUser()"><i class="fa fa-plus-circle"></i>&nbsp;&nbsp;Add an entry</a>
    </div>
    <h3 class="panel-title">
      <i class="fa fa-users"></i>&nbsp;&nbsp;&nbsp;&nbsp;<span v-html="group.dn"/>
    </h3>
  </div>
  <div class="panel-body">
    <div class="row">
      <div class="col-md-12">
        <table class="table table-bordered table-striped table-hover table-heading table-datatable" :id="id"></table>
      </div>
    </div>
  </div>
  <div class="modal" :id="modalId()" role="dialog" tabindex="-1" :aria-labelled-by="id" aria-hidden="true">
      <div class="modal-dialog">
          <div class="modal-content" :id="modalContentId()">
          </div>
      </div>
  </div>
</div>
`

let UserListComponent = Vue.component("UserList", {
  template: users_list_template,
  props: {
    group_keys: Array,
    user_keys: Array,
    group: Object,
    id: String
  },
  data() {
    return {
      users: null,
    }
  },

  mounted() {
    setTimeout(() => {
      this.getUsers()
    }, 100)
  },

  methods: {
    renderTarget() {
      return `#${this.id}`
    },

    modalId() {
        return `modal-${this.id}`
    },

    modalContentId() {
        return `modal-content-${this.id}`
    },

    getUsers() {
      axios.get(ldap_view_api_uri, {params: {"object_type": "users", group_dn: this.group.dn}})
        .then((response) => {
          this.users = response.data.users
          this.initTable()
        })
    },

    initTable() {
      if (this.user_table) {
        this.user_table.fnDestroy()
        $(`#${this.id}`).empty()
      }

      let columns = [{
        sTitle: "dn",
        name: "dn",
        aTargets: [0],
        mData: "dn"
      }]

      let target_index = 1;
      for (let key of this.user_keys) {
        columns.push({
          sTitle: key,
          name: key,
          aTargets: [target_index],
          mData: key,
          mRender: (data, type, row) => {
            let html = []
            for (let elem of data) 
              html.push(`<label class="label label-info label-ldap">${elem}</label>`)
            return html.join("&nbsp;&nbsp;")
          }
        })

        target_index++;
      }

      columns.push({
        sTitle: gettext('Action'),
        name: "action",
        aTargets: [target_index],
        mData: "dn",
        sWidth: "10%",
        mRender: () => {
            let html = [
                `<button class="btn btn-xs btn-info btn-edit"><i class="fa fa-edit"></i></button>`,
                `<button class="btn btn-xs btn-danger btn-delete"><i class="fa fa-trash"></i></button>`,
            ]

            return html.join("&nbsp;")
        }
      })

      this.user_table = $(`#${this.id}`).dataTable({
        order: [[0, "desc"]],
        iDisplayLength: 10,
        aoColumns: columns,
        aaData: this.users,
        fnCreatedRow: (nRow, aData, iDataIndex) => {
            $(nRow).find('.btn-edit').on('click', (e) => {
                e.stopPropagation()

                let bus = new Vue()
                bus.$on('updateUserList', () => {
                  $(`#${this.modalContentId()}`).html("")
                  $(`#modal-${this.id}`).modal('hide')
                  this.getUsers()
                })

                let comp = new UserFormComponent({
                    propsData: {
                        user_edit_keys: this.user_keys,
                        group_dn: this.group.dn,
                        user_data: aData,
                        user_bus: bus
                    }
                }).$mount()

                $(`#modal-${this.id}`).modal('show')
                $(`#${this.modalContentId()}`).html(comp.$el)
            })

            $(nRow).find('.btn-delete').on('click', (e) => {
                e.stopPropagation()

                new PNotify({
                    title: gettext('Confirmation'),
                    text: gettext("Delete entry: ") + aData.dn + " ?",
                    icon: "fa fa-trash",
                    hide: false,
                    confirm: {confirm: true},
                    buttons: {closer: false, sticket: false},
                    history: {history: false}
                  }).get().on('pnotify.confirm', () => {           
                    axios.delete(ldap_view_api_uri,  {data: {dn: aData.dn}})
                      .then((response) => {
                        if (response.status === 200) {
                          notify('success', gettext('Success'), gettext('Entries deleted'))
                          this.getUsers()
                        }
                      })
                  })
            })
        }
      })
    },

    addUser(){
      let bus = new Vue()
      bus.$on("updateUserList", () => {
        $(`#${this.modalContentId()}`).html("")
        $(`#modal-${this.id}`).modal('hide')
        this.getUsers()
      })

      let comp = new UserFormComponent({
        propsData: {
          user_edit_keys: this.user_keys,
          group_dn: this.group.dn,
          user_bus: bus,
          user_data: {}
        }
      }).$mount()

      $(`#modal-${this.id}`).modal('show')
      $(`#${this.modalContentId()}`).html(comp.$el)
    }
  }
})