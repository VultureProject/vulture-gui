Vue.component('vue-tags-input', vueTagsInput.vueTagsInput)

let user_form_template = `
<form class="form-horizontal" @submit.prevent="saveUser()">
    <div class="modal-header">
        <button type="button" class="close" data-dismiss="modal"><i class="pci-cross pci-circle"></i></button>
        <h3 class="modal-title">${gettext("User form")}</h3>
    </div>
    <div class="modal-body">
        <div class="row">
            <div class="col-md-12 form-group" v-for="key in user_edit_keys">
                <label class="col-sm-3 control-label text-right text-bold" v-html="key"/>
                <div class="col-sm-9">
                    <input type="text" class="form-control" v-model="user_data[key]"/>
                </div>
            </div>
            <div class="col-md-12 form-group">
                <label class="col-sm-3 control-label text-right text-bold">${gettext("Password")}</label>
                <div class="col-sm-9">
                    <input type="password" class="form-control" v-model="userPassword"/>
                </div>
            </div>
        </div>
    </div>
    <div class="modal-footer">
        <button type="submit" class="btn btn-success"><i class="fa fa-save"></i>&nbsp;${gettext("Save")}</button>
    </div>
</form>
`

let UserFormComponent = Vue.component("UserForm", {
    template: user_form_template,
    props: {
        user_bus: Object,
        user_data: Object,
        user_edit_keys: Array,
        edit: {
            type: Boolean,
            default: false
        }
    },

    data() {
        return {
            userPassword: ""
        }
    },

    mounted() { },

    methods: {
        formatTags(tmp_tags) {
            if (!tmp_tags)
                return

            let tags = []
            for (let tmp of tmp_tags) {
                if (!tmp.text)
                    tags.push({ text: tmp })
                else
                    tags.push(tmp)
            }

            return tags
        },

        saveUser() {
            if (this.edit) {
                axios.put(idp_api_users_uri, this.user_data)
                    .then((response) => {
                        if (response.status === 200) {
                            notify('success', gettext("Success"), gettext("User successfully updated"))
                            this.user_bus.$emit('updateUserList')
                        }
                    })
                    .catch((error) => {
                        console.error(error.response.data)
                    })
            } else {
                axios.post(idp_api_users_uri, this.user_data)
                    .then((response) => {
                        if (response.status === 201) {
                            notify('success', gettext('Success'), gettext("User successfully added"))
                            this.user_bus.$emit('updateUserList')
                        }
                    })
                    .catch((error) => {
                        console.error(error.response.data)
                    })
            }
        }
    }
})