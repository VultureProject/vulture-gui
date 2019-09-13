$(document).ready(() => {
    setModDefenderSelect2()
    let updateButton = $('#mod-defender-update-ruleset-button')

    updateButton.on('click', (event) => {
        event.stopPropagation()
        event.preventDefault()
        saveRawRules()
    })

    const currentRuleId = $('#id_defender_ruleset').val()

    if (currentRuleId !== '' && currentRuleId !== undefined && currentRuleId !== null) {
        setRawRulesTextArea(currentRuleId)
        updateButton.prop('disabled', false)
    } else {
        updateButton.prop('disabled', true)
    }
})

function setModDefenderSelect2 () {
    let modDefenderSelector = $('#id_defender_ruleset')

    modDefenderSelector.select2()

    modDefenderSelector.on('select2:select', (event) => {
        const currentRuleId = event.params.data.id

        if (currentRuleId !== '' && currentRuleId !== undefined && currentRuleId !== null) {
            setRawRulesTextArea(currentRuleId)
            $('#mod-defender-update-ruleset-button').prop('disabled', false)
        } else {
            $('#mod-defender-update-ruleset-button').prop('disabled', true)
        }
    })
}

function setRawRulesTextArea (rulesetID) {
    let modDefenderTextArea = $('#mod-defender-raw-rules')
    modDefenderTextArea.val('')

    const currentUrl = `${defenderRawRulesetUrl.substr(0, defenderRawRulesetUrl.length - 3)}${rulesetID}/`

    $.get(currentUrl, () => {}).done((response) => {
        if (!check_json_error(response)) {
            console.error(`Something wrong happened: "${response.error}". Please check logs. Stopping.`)
            return
        }

        modDefenderTextArea.val(response.raw_rules)
    })
}

function saveRawRules () {
    let modDefenderTextArea = $('#mod-defender-raw-rules')
    const rulesetID = $('#id_defender_ruleset').val()

    const rawRules = modDefenderTextArea.val()
    const currentUrl = `${defenderRawRulesetUrl.substr(0, defenderRawRulesetUrl.length - 3)}${rulesetID}/`

    $.post(currentUrl, {raw_rules: rawRules}).done((response) => {
        if (!check_json_error(response)) {
            console.error(`Something wrong happened: "${response.error}". Please check logs. Stopping.`)
            return
        }

        notify('success', gettext('Success'), response.message)
    })
}