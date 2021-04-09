let idp_view = new Vue({
    el: "#idp_view",
    data: () => ({
        users: null,
        idp_repository: null
    }),

    mounted() {
        axios.get(portal_api_uri)
            .then((response) => {
                this.idp_repository = response.data.data
                this.user_keys = [
                    "username",
                    "email",
                    "mobile",
                    "smartcardid",
                    "is_locked",
                    "need_change_password"
                ]
                this.getUsers()
            })
    },

    methods: {
        getUsers() {
            axios.get(idp_api_uri, { params: { object_type: "users" } })
                .then((response) => {
                    this.users = response.data.data
                    console.log(this.users)
                    this.initTable()
                })
        },

        addUser() {
            let bus = new Vue()
            bus.$on("updateUserList", () => {
                $("#modalAddUserContent").html("")
                $("#modalAddUser").modal('hide')
                this.getUsers()
            })

            let comp = new UserFormComponent({
                propsData: {
                    user_edit_keys: this.user_keys,
                    user_bus: bus,
                    user_data: {}
                }
            }).$mount()

            $("#modalAddUser").modal('show')
            $("#modalAddUserContent").html(comp.$el)
        },

        initTable() {
            if (this.user_table) {
                this.user_table.fnDestroy()
                $(`#${this.id}`).empty()
            }

            let columns = []
            let target_index = 0;
            for (let key of this.user_keys) {
                columns.push({
                    sTitle: key,
                    name: key,
                    aTargets: [target_index],
                    defaultContent: "",
                    mData: key,
                    mRender: (data, type, row) => {
                        if (!data)
                            return ""

                        let html = []
                        html.push(`<label class="label label-info label-ldap">${data}</label>`)
                        return html.join("&nbsp;&nbsp;")
                    }
                })

                target_index++;
            }

            columns.push({
                sTitle: gettext('Action'),
                name: "action",
                aTargets: [target_index],
                mData: "username",
                sWidth: "10%",
                mRender: () => {
                    let html = [
                        `<button class="btn btn-xs btn-info btn-edit"><i class="fa fa-edit"></i></button>`,
                        `<button class="btn btn-xs btn-danger btn-delete"><i class="fa fa-trash"></i></button>`,
                    ]

                    return html.join("&nbsp;")
                }
            })

            this.user_table = $("#table_users").dataTable({
                order: [[0, "desc"]],
                iDisplayLength: 10,
                aoColumns: columns,
                aaData: this.users,
                fnCreatedRow: (nRow, aData, iDataIndex) => {
                    $(nRow).find('.btn-edit').on('click', (e) => {
                        e.stopPropagation()

                        let bus = new Vue()
                        bus.$on('updateUserList', () => {
                            $("#modalAddUserContent").html("")
                            $("#modalAddUser").modal('hide')
                            this.getUsers()
                        })

                        let comp = new UserFormComponent({
                            propsData: {
                                user_edit_keys: this.user_keys,
                                user_data: aData,
                                user_bus: bus,
                                edit: true
                            }
                        }).$mount()

                        $("#modalAddUser").modal('show')
                        $("#modalAddUserContent").html(comp.$el)
                    })

                    $(nRow).find('.btn-delete').on('click', (e) => {
                        e.stopPropagation()

                        new PNotify({
                            title: gettext('Confirmation'),
                            text: gettext("Delete entry: ") + aData.username + " ?",
                            icon: "fa fa-trash",
                            hide: false,
                            confirm: { confirm: true },
                            buttons: { closer: false, sticket: false },
                            history: { history: false }
                        }).get().on('pnotify.confirm', () => {
                            axios.delete(idp_api_users_uri, { data: { username: aData.username } })
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
        }
    }
})