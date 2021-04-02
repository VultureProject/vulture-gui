
let template_edit_vue = new Vue({
    el: "#template_edit_vue",
    delimiters: ['${', '}'],
    data: {
        django_editors: [
            'html_login', 'html_logout', 'html_learning', 'html_self', 'html_password', 'email_body',
            'html_otp', 'html_registration', 'email_register_body', 'html_message', 'html_error'
        ],
        editors: {}
    },

    mounted() {
        let editorOptions = {
            maxLines: 50,
            fontSize: 13,
            showGutter: true,
            cursorStyle: 'slim',
            enableSnippets: true,
            showLineNumbers: true,
            showFoldWidgets: true,
            showPrintMargin: true,
            displayIndentGuides: true,
            enableLiveAutocompletion: true,
            enableBasicAutocompletion: true,
            autoScrollEditorIntoView: true
        }

        setTimeout(() => {
            this.css_editor = ace.edit("id_css");
            this.css_editor.session.setMode("ace/mode/css");
            this.css_editor.setTheme("ace/theme/monokai");
            this.css_editor.resize()
            this.css_editor.session.setUseWrapMode(true);
            this.css_editor.setOptions(editorOptions)

            for (let id of this.django_editors) {
                let tmp = ace.edit(`id_${id}`)
                tmp.session.setMode("ace/mode/django");
                tmp.setTheme("ace/theme/monokai");
                tmp.resize()
                tmp.session.setUseWrapMode(true);
                tmp.setOptions(editorOptions)

                this.editors[id] = tmp
            }
        }, 200)
    },

    methods: {
        preview(id) {
            let css = this.css_editor.getValue()
            let html = this.editors[id].getValue()

            switch (id) {
                case "html_error":
                    var win = window.open('', 'error_preview');
                    var error_403 = $('#id_html_error_403').val();
                    var error_404 = $('#id_html_error_404').val();
                    var error_405 = $('#id_html_error_405').val();
                    var error_406 = $('#id_html_error_406').val();
                    var error_500 = $('#id_html_error_500').val();
                    var error_501 = $('#id_html_error_501').val();
                    var error_502 = $('#id_html_error_502').val();
                    var error_503 = $('#id_html_error_503').val();
                    var error_504 = $('#id_html_error_504').val();

                    //css = css.replace('"static', '"/static');
                    html = html.replace('\{\{style\}\}', "<style>" + css + "</style>");
                    for (let [image_tag, values] of Object.entries(images_list)) {
                        html = html.replace(`\{\{${image_tag}\}\}`, values.preview)
                    }
                    html = html.replace('\{\{message\}\}', error_403 + "<br>" + error_404 + "<br>" + error_405 + "<br>" + error_406 + "<br>" + error_500 + "<br>" + error_501 + "<br>" + error_502 + "<br>" + error_503 + "<br>" + error_504);
                    win.document.write(html);
                    break
                case "html_login":
                    var win = window.open('', 'login_preview');

                    for (let [image_tag, values] of Object.entries(images_list)) {
                        html = html.replace(`\{\{${image_tag}\}\}`, values.preview)
                    }

                    html = html.replace('\{\{style\}\}', '<style>' + css + '</style>');
                    html = html.replace("\{\{form_begin\}\}", "<form action='/login' method='POST' autocomplete='off'>");
                    html = html.replace("\{\{form_end\}\}", "</form>");
                    html = html.replace("\{\{input_login\}\}", "<input type='text' name='vltprtlsrnm' class='form-control' placeholder='Login'>");
                    html = html.replace("\{\{input_password\}\}", "<input type='password' class='form-control' placeholder='Password' name='vltprtlpsswrd'>");
                    html = html.replace("\{\{input_submit\}\}", "<button class='btn btn-lg btn-warning btn-block btn-signin' type='submit'>Sign in</button>");
                    html = html.replace("\{\{input_captcha\}\}", "<input type='text' class='form-control' placeholder='Captcha' name='vltprtlcaptcha'>");
                    html = html.replace("\{\{captcha\}\}", "<img id='captcha' src='/static/img/example_captcha.png' alt='captcha'/>");
                    html = html.replace("\{\{lostPassword\}\}", "/self/lost");
                    html = html.replace("\{% csrf_token %\}", "");
                    html = html.replace("\{% autoescape off %\}", "");
                    html = html.replace("\{% endautoescape %\}", "");
                    //html=html.replace("templates", "");
                    html = html.replace("\{\{error_message\}\}", "This is a test error message");
                    html = html.replace(/\{\%(.*)\%\}/g, "");
                    win.document.write(html);
                    break;

                case "html_logout":
                    var win = window.open('', 'logout_preview');
                    for (let [image_tag, values] of Object.entries(images_list)) {
                        html = html.replace(`\{\{${image_tag}\}\}`, values.preview)
                    }
                    html = html.replace('\{\{style\}\}', '<style>' + css + '</style>');
                    html = html.replace('\{\{app_url\}\}', 'http://app.example.com/test/');
                    html = html.replace("\{% csrf_token %\}", "");
                    html = html.replace("\{% autoescape off %\}", "");
                    html = html.replace("\{% endautoescape %\}", "");
                    html = html.replace(/\{\%(.*)\%\}/g, "");
                    win.document.write(html);
                    break;

                case "html_learning":
                    var win = window.open('', 'learning_preview');
                    for (let [image_tag, values] of Object.entries(images_list)) {
                        html = html.replace(`\{\{${image_tag}\}\}`, values.preview)
                    }
                    html = html.replace('\{\{style\}\}', '<style>' + css + '</style>');
                    html = html.replace("\{\{form_begin\}\}", "<form action='/login' method='POST' autocomplete='off'>");
                    html = html.replace("\{\{form_end\}\}", "</form>");
                    html = html.replace("\{\{input_submit\}\}", "<div class='form-group'><input type='text' class='form-control' name='basic_username' value='Sample Value' /></div><div class='form-group'><label class='label'></label><input type='submit' class='btn btn-warning btn-block' value='Ok' /></div>");
                    html = html.replace("\{% csrf_token %\}", "");
                    html = html.replace("\{% autoescape off %\}", "");
                    html = html.replace("\{% endautoescape %\}", "");
                    html = html.replace(/\{\%(.*)\%\}/g, "");
                    win.document.write(html);
                    break;

                case "html_self":
                    var win = window.open('', 'self_preview');
                    for (let [image_tag, values] of Object.entries(images_list)) {
                        html = html.replace(`\{\{${image_tag}\}\}`, values.preview)
                    }
                    html = html.replace('\{\{style\}\}', '<style>' + css + '</style>');
                    html = html.replace("\{\{form_begin\}\}", "<form action='/login' method='POST' autocomplete='off'>");
                    html = html.replace("\{\{form_end\}\}", "</form>");
                    html = html.replace("\{% csrf_token %\}", "");
                    html = html.replace("\{% autoescape off %\}", "");
                    html = html.replace("\{% endautoescape %\}", "");
                    html = html.replace("\{\{changePassword\}\}", "/self/change");
                    html = html.replace("\{\{error_message\}\}", "This is a test error message");
                    //html=html.replace("templates", "");
                    html = html.replace(/\{\%(.*)\%\}/g, "");
                    win.document.write(html);
                    break;

                case "html_password":
                    var win = window.open('', 'password_preview');
                    for (let [image_tag, values] of Object.entries(images_list)) {
                        html = html.replace(`\{\{${image_tag}\}\}`, values.preview)
                    }
                    html = html.replace('\{\{style\}\}', '<style>' + css + '</style>');
                    html = html.replace("\{\{form_begin\}\}", "<form action='/login' method='POST' autocomplete='off'>");
                    html = html.replace("\{\{form_end\}\}", "</form>");
                    html = html.replace("\{\{input_password_old\}\}", "<input type='password' name='password_old' value='OldPassword' class='form-control'>");
                    html = html.replace("\{\{input_password_1\}\}", "<input type='password' name='password_1' value='NewPassW0rD' class='form-control'>");
                    html = html.replace("\{\{input_password_2\}\}", "<input type='password' name='password_2' value='NewPassW0rD' class='form-control'>");
                    html = html.replace("\{\{input_email\}\}", "<input type='text' name='email' value='sample@example.com' class='form-control'>");
                    html = html.replace("\{\{input_submit\}\}", "<input type='submit' class='btn btn-lg btn-warning btn-block btn-signin' value='Ok' />");
                    html = html.replace("\{\{input_submit\}\}", "<input type='submit' class='btn btn-lg btn-warning btn-block btn-signin' value='Ok' />");
                    html = html.replace("\{% csrf_token %\}", "");
                    html = html.replace("\{% autoescape off %\}", "");
                    html = html.replace("\{% endautoescape %\}", "");
                    //html=html.replace("../templates", "");
                    html = html.replace(/\{\%(.*)\%\}/g, "");
                    win.document.write(html);
                    break;

                case "html_otp":
                    var win = window.open('', 'otp_preview');
                    for (let [image_tag, values] of Object.entries(images_list)) {
                        html = html.replace(`\{\{${image_tag}\}\}`, values.preview)
                    }
                    html = html.replace('\{\{style\}\}', '<style>' + css + '</style>');
                    html = html.replace("\{\{form_begin\}\}", "<form action='/login' method='POST' autocomplete='off'>");
                    html = html.replace("\{\{form_begin\}\}", "<form action='/login' method='POST' autocomplete='off'>");
                    html = html.replace("\{\{form_end\}\}", "</form>");
                    html = html.replace("\{\{form_end\}\}", "</form>");
                    html = html.replace("\{\{input_submit\}\}", "<button class='btn btn-lg btn-warning btn-block btn-signin' type='submit'>Sign in</button>");
                    html = html.replace("\{\{input_key\}\}", "<input type='text' class='form-control' placeholder='Key' name='vltprtlkey'>");
                    html = html.replace("\{\{resend_button\}\}", "<button class='btn btn-lg btn-warning btn-block btn-signin' name='vltotpresend' value='yes' type='submit'>Resend mail/sms</button>");
                    html = html.replace("\{% csrf_token %\}", "");
                    html = html.replace("\{% autoescape off %\}", "");
                    html = html.replace("\{% endautoescape %\}", "");
                    //html=html.replace("templates", "");
                    html = html.replace("\{\{error_message\}\}", "<b> Error </b> <br> This is a test error message");
                    html = html.replace("\{\{qrcode\}\}", 'src="data:image/jpeg;base64, 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"');
                    html = html.replace(/\{\%(.*)\%\}/g, "");
                    win.document.write(html);
                    break;

                case "html_registration":
                    var win = window.open('', 'registration_preview');
                    for (let [image_tag, values] of Object.entries(images_list)) {
                        html = html.replace(`\{\{${image_tag}\}\}`, values.preview)
                    }
                    html = html.replace('\{\{style\}\}', '<style>' + css + '</style>');
                    html = html.replace("\{\{form_begin\}\}", "<form action='/login' method='POST' autocomplete='off'>");
                    html = html.replace("\{\{form_end\}\}", "</form>");
                    html = html.replace("\{\{input_email\}\}", "<input type='text' name='vltrgstremail' value='Email' class='form-control'>");
                    html = html.replace("\{\{error_message\}\}", "An error occurred <br> <b>Please contact your administrator</b>");
                    html = html.replace("\{\{input_username\}\}", "<input type='text' name='username' value='Username' class='form-control'>");
                    html = html.replace("\{\{captcha\}\}", "<img id='captcha' src='/static/img/example_captcha.png' alt='captcha'/>");
                    html = html.replace("\{\{input_captcha\}\}", "<input type='text' name='captcha' value='Captcha' class='form-control'>");
                    html = html.replace("\{\{input_phone\}\}", "<input type='text' name='phone' value='Phone number' class='form-control'>");
                    html = html.replace("\{\{input_password_1\}\}", "<input type='password' name='password_1' value='Password' class='form-control'>");
                    html = html.replace("\{\{input_password_2\}\}", "<input type='password' name='password_2' value='Password' class='form-control'>");
                    html = html.replace("\{\{input_submit\}\}", "<input type='submit' class='btn btn-lg btn-warning btn-block btn-signin' value='Ok' />");
                    html = html.replace("\{\{input_submit\}\}", "<input type='submit' class='btn btn-lg btn-warning btn-block btn-signin' value='Ok' />");
                    html = html.replace("\{% csrf_token %\}", "");
                    html = html.replace("\{% autoescape off %\}", "");
                    html = html.replace("\{% endautoescape %\}", "");
                    //html=html.replace("../templates", "");
                    html = html.replace(/\{\%(.*)\%\}/g, "");
                    win.document.write(html);
                    break;

                case "html_message":
                    var win = window.open('', 'message_preview');
                    for (let [image_tag, values] of Object.entries(images_list)) {
                        html = html.replace(`\{\{${image_tag}\}\}`, values.preview)
                    }
                    html = html.replace('\{\{style\}\}', '<style>' + css + '</style>');
                    html = html.replace("\{\{message\}\}", "This is an example message.");
                    html = html.replace("\{% csrf_token %\}", "");
                    html = html.replace("\{% autoescape off %\}", "");
                    html = html.replace("\{% endautoescape %\}", "");
                    html = html.replace("../templates", "");
                    html = html.replace("\{\{link_redirect\}\}", "#");
                    html = html.replace("\{\{error_message\}\}", "This is a test error message");
                    html = html.replace(/\{% if [\w\W]* %\}([\s\w\W]*)\{% endif %\}/g, "$1");
                    html = html.replace(/\{\%(.*)\%\}/g, "");
                    win.document.write(html);
                    break;
            }
        },

        save_form() {
            var txt = $('#save_form_btn').html();
            $('#save_form_btn').html('<i class="fa fa-spinner fa-spin"></i>');
            $('#save_form_btn').prop('disabled', 'disabled');

            let tmp_form = $('#portal_template_form').serializeArray()
            let form = {}
            for (let i of tmp_form) {
                form[i.name] = i.value
            }

            form['css'] = this.css_editor.getValue()

            for (let [id, editor] of Object.entries(this.editors)) {
                form[id] = editor.getValue()
            }

            if (object_id === "None") {
                axios.post(portal_template_api_uri, form)
                    .then((response) => {
                        notify('success', gettext('Success'), response.data.message)
                        setTimeout(() => {
                            window.location.href = portal_template_uri
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
                axios.put(portal_template_api_uri + object_id, form)
                    .then((response) => {
                        notify('success', gettext('Success'), response.data.message)
                        setTimeout(() => {
                            window.location.href = portal_template_uri
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
    }
})
