// HISTORY FUNCTIONS //////////////////////////////////////////////////////////
const MAX_HISTORY = 5
let history = []
let currentHistoryIndex = 0
let inputHistory = {}

// object used to display a rule's description
const mainRules = {
    '2': ['Big request', ''],
    '10': ['Uncommon hex encoding', '%00'],
    '17': ['Libinjection SQL', ''],
    '18': ['Libinjection XSS', '&ltscript&gt'],
    '1000': ['sql keywords', new RegExp('select|union|update|delete|insert|table|from|ascii|hex|unhex|drop', 'g')],
    '1001': ['double quote', '&quot;'],
    '1002': ['0x, possible hex encoding', '0x'],
    '1003': ['mysql comment (/*)', '/*'],
    '1004': ['mysql comment (*/)', '*/'],
    '1005': ['mysql keyword (|)', '|'],
    '1006': ['mysql keyword (&&)', '&&'],
    '1007': ['mysql comment (--)', '--'],
    '1008': ['semicolon', ';'],
    '1009': ['equal sign in var', '&#61;'],
    '1010': ['open parenthesis', '('],
    '1011': ['close parenthesis', ')'],
    '1013': ['simple quote', "'"],
    '1015': ['comma', ','],
    '1016': ['mysql comment (#)', '&#35;'],
    '1017': ['double arobase (@@)', '@@'],

    '1100': ['http:// scheme', 'http://'],
    '1101': ['https:// scheme', 'https://'],
    '1102': ['ftp:// scheme', 'ftp://'],
    '1103': ['php:// scheme', 'php://'],
    '1104': ['sftp:// scheme', 'sftp://'],
    '1105': ['zlib:// scheme', 'zlib://'],
    '1106': ['data:// scheme', 'data://'],
    '1107': ['glob:// scheme', 'glob://'],
    '1108': ['phar:// scheme', 'phar://'],
    '1109': ['file:// scheme', 'file://'],
    '1110': ['gopher:// scheme', 'gopher://'],

    '1200': ['..', 'double dot'],
    '1202': ['unix file probe', '/etc/passwd'],
    '1203': ['windows path', 'c:\\\\'],
    '1204': ['cmd probe', 'cmd.exe'],
    '1205': ['backslash', '\\'],

    '1302': ['html open tag', '&lt;'],
    '1303': ['html close tag', '&gt;'],
    '1310': ['open square backet ([)', '['],
    '1311': ['close square bracket (])', ']'],
    '1312': ['tilde (~)', '~'],
    '1314': ['grave accent (`)', '`'],
    '1315': ['double encoding', new RegExp('%[2|3].', 'g')],

    '1400': ['utf7/8 encoding', '&#'],
    '1401': ['M$ encoding', '%u'],

    '1500': ['asp/php file upload', new RegExp('\.ph|\.asp|\.ht', 'g')]
}

function saveToHistory (data) {
    history.push(data)

    if (currentHistoryIndex + 1 < history.length - 1) {
        history.splice(currentHistoryIndex + 1, history.length - currentHistoryIndex - 2)
    }

    setHistoryIndex(Math.min(history.length - 1, MAX_HISTORY))

    if (history.length > MAX_HISTORY) {
        history.splice(0, 1)
    }
}

function restoreHistory (index) {
    if (index < 0 || index > history.length) return

    setHistoryIndex(index)
    updateRuleDatatable(history[index])
}

function setHistoryIndex (index) {
    let previousButton = $('#btn-previous-whitelist-datatable')
    let nextButton = $('#btn-next-whitelist-datatable')

    currentHistoryIndex = index
    previousButton.prop('disabled', true)
    nextButton.prop('disabled', true)

    if (currentHistoryIndex > 0) {
        previousButton.prop('disabled', false)
    }

    if (currentHistoryIndex < history.length - 1) {
        nextButton.prop('disabled', false)
    }
}
///////////////////////////////////////////////////////////////////////////////

// UTILITY FUNCTIONS //////////////////////////////////////////////////////////
// return a new string with toDeleteNb characters deleted from fromIndex, replaced with stringToAdd
function splice (string, fromIndex, toDeleteNb, stringToAdd) {
    return string.slice(0, fromIndex) + stringToAdd + string.slice(fromIndex + Math.abs(toDeleteNb))
}

// take a string, and make it usable in a regex
function regexify (string) {
    return string.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&')
}

function duplicatesFilter (value, index, self) {
    return self.indexOf(value) === index
}
///////////////////////////////////////////////////////////////////////////////

// RULES FUNCTIONS ////////////////////////////////////////////////////////////
// Merge functions ------------------------------------------------------------
function mergeExprs (exprArray, type) {
    if (exprArray.length === 1) {
        return exprArray[0]
    }

    if (window.confirm(gettext(`Do you want to merge the ${type}s as a wildcard (*)?`))) {
        return '*'
    }

    let exprRegexifiedArray = []

    for (const expr of exprArray) {
        if (expr === '*') return expr

        if (expr instanceof RegExp) {
            const pattern = expr.toString()

            exprRegexifiedArray = exprRegexifiedArray.concat(
                pattern.substring(1, pattern.length - 1
            ).split('|'))
        } else {
            exprRegexifiedArray.push(regexify(expr))
        }
    }

    return new RegExp(exprRegexifiedArray.filter(duplicatesFilter).join('|'))
}

function mergeRuleIDs (ruleIDArray) {
    return ruleIDArray.filter(duplicatesFilter)
}

function resetRuleDatatable (event) {
    let ruleDatatable = $('#whitelist-datatable')
    ruleDatatable.DataTable().fnDestroy()
    generateAndDisplayRuleDatatable()
    setHistoryIndex(0)
    history = []
}

function updateRuleDatatable (whitelistArray) {
    let ruleDatatable = $('#whitelist-datatable')
    ruleDatatable.DataTable().fnDestroy()
    displayRuleDatatable(whitelistArray)
}

// Include functions ----------------------------------------------------------
function isRuleIDArrayIncluded (ruleIDArray, ruleIDArrayToBeIncluded) {
    for (const ruleID of ruleIDArrayToBeIncluded) {
        let isIncluded = false

        for (const otherRuleID of ruleIDArray) {
            if (otherRuleID === ruleID) {
                isIncluded = true
                break
            }
        }

        if (!isIncluded) return false
    }

  return true
}

function isZoneIncluded (zone, zoneToBeIncluded) {
    return zone === zoneToBeIncluded
}

function isExprIncluded (expr, exprToBeIncluded) {
    if ((typeof expr === 'string' || expr instanceof String) && expr === '*') return true

    if ((typeof exprToBeIncluded === 'string' || exprToBeIncluded instanceof String) && exprToBeIncluded === '*') {
        return false
    }

    let exprString = expr
    let exprToBeIncludedString = exprToBeIncluded

    if (exprString instanceof RegExp) {
        exprString = exprString.toString()
        exprString = exprString.substring(1, exprString.length - 1)
    }

    if (exprToBeIncludedString instanceof RegExp) {
        exprToBeIncludedString = exprToBeIncludedString.toString()
        exprToBeIncludedString = exprToBeIncludedString.substring(1, exprToBeIncludedString.length - 1)
    }

    if (exprString === exprToBeIncludedString) return true

    if (expr instanceof RegExp && !(exprToBeIncluded instanceof RegExp)) {
        return exprToBeIncluded.match(expr) !== null
    }

    return false
}

function isRuleIncluded (rule, ruleToBeIncluded) {
    return isExprIncluded(rule.url, ruleToBeIncluded.url) &&
        isRuleIDArrayIncluded(rule.id, ruleToBeIncluded.id) &&
        isExprIncluded(rule.key, ruleToBeIncluded.key) &&
        isExprIncluded(rule.value, ruleToBeIncluded.value) &&
        isZoneIncluded(rule.zone, ruleToBeIncluded.zone)
}

// Merge functions ------------------------------------------------------------
function reduceRules (newRule, ruleArray) {
    for (let ruleIndex = 1; ruleIndex < ruleArray.length; ++ruleIndex) {
        let currentRule = ruleArray[ruleIndex]

        if (isRuleIncluded(newRule, currentRule)) {
            ruleArray.splice(ruleIndex, 1)
            --ruleIndex
        } else if (isRuleIncluded(currentRule, newRule)) {
            ruleArray[0] = currentRule
            ruleArray.splice(ruleIndex, 1)
            --ruleIndex
        }
    }
}

function mergeRules (event) {
    try {
        const ruleCheckboxes = $('.rule-checkbox')
        let rowsToMerge = []

        ruleCheckboxes.each(function (index) {
            const ruleCheckbox = $(this)

            if (!ruleCheckbox.prop('checked')) return

            const ruleId = ruleCheckbox.attr('id')
            rowsToMerge.push(ruleId.substring(14, ruleId.length))
        })

        if (rowsToMerge.length <= 0) throw new Error('No rules to merge')

        let ruleArray = $('#whitelist-datatable').DataTable().fnGetData()
        let toMergeArray = []
        let matchedType = undefined
        let zone = undefined

        for (const index of rowsToMerge) {
            const ruleToMerge = ruleArray[index]

            if (zone === undefined) {
                zone = ruleToMerge.zone
            } else {
                // we cannot merge two different rule types together
                if (ruleToMerge.zone !== zone) {
                    notify('error', gettext('Error'), gettext('Zones have to be the same'))
                    return
                }
            }

            if (matchedType === undefined) {
                matchedType = ruleToMerge.matched
            } else {
                // we cannot merge two different rule types together
                if (ruleToMerge.matched !== matchedType) continue
            }

            toMergeArray.push(ruleToMerge)
        }

        const newRule = mergeRule(toMergeArray)
        let toShift = 0

        for (const index of rowsToMerge) {
            ruleArray.splice(index - toShift, 1)
            ++toShift
        }

        ruleArray.unshift(newRule)
        reduceRules(newRule, ruleArray)

        saveToHistory(ruleArray)
        updateRuleDatatable(ruleArray)
    } catch (error) {
        notify('error', gettext('Error'), error.message)
        throw error
    }
}

function mergeRule (whitelistArray) {
    if (whitelistArray.length <= 0) throw new Error('There are no rules to merge')

    let keyArray = []
    let valueArray = []
    let urlArray = []
    let ruleIDArray = []

    for (const dataDescr of  whitelistArray) {
        keyArray.push(dataDescr.key)
        valueArray.push(dataDescr.value)
        urlArray.push(dataDescr.url)
        ruleIDArray = ruleIDArray.concat(dataDescr.id)
    }

    keyArray = keyArray.filter(duplicatesFilter)
    valueArray = valueArray.filter(duplicatesFilter)
    urlArray = urlArray.filter(duplicatesFilter)
    ruleIDArray = ruleIDArray.filter(duplicatesFilter)

    const mergedKeys = mergeExprs(keyArray, 'key')
    const mergedValues = mergeExprs(valueArray, 'value')
    const mergedUrls = mergeExprs(urlArray, 'url')
    const mergedRuleIDs = mergeRuleIDs(ruleIDArray)

    return {
        zone: whitelistArray[0].zone,
        key: mergedKeys,
        value: mergedValues,
        url: mergedUrls,
        id: mergedRuleIDs,
        matched: whitelistArray[0].matched // at least one element exists, because of the previous checks
    }
}

// Views functions ------------------------------------------------------------
// fetch the whitelist, in order to display them in a popped up modal
function generateAndDisplayRuleDatatable () {
    let rules = {}

    try {
        rules = $('#queryBuilder').queryBuilder('getMongo')
    } catch (error) {
        console.error(error)
        console.error('An error has occurred. Stopping.')
        return
    }

    let startDate = reportrange.data('daterangepicker').startDate
    let endDate = reportrange.data('daterangepicker').endDate

    startDate = startDate.format('YYYY-MM-DDTHH:mm:ssZZ')
    endDate = endDate.format('YYYY-MM-DDTHH:mm:ssZZ')

    const data = {
        'frontend_name': selected_app,
        'startDate': startDate.format(),
        'endDate': endDate.format(),
        'rules': JSON.stringify(rules)
    }

    $('#modal-whitelist-body').html('')
    // we reset the history
    history = []
    currentHistoryIndex = 0
    let loadingIcon = $('#whitelist-datatable-loading')
    let datatableContainer = $('#whitelist-datatable-container')
    loadingIcon.show()
    datatableContainer.hide()
    $('#modal-whitelist').modal('show')

    $.ajax({
        type: 'post',
        timeout: 0,
        url: request_defender_whitelist,
        data: data
    }).done((response) => {
        if (!check_json_error(response)) {
            console.error(`Something wrong happened: "${response.error}". Please check logs. Stopping.`)
            return
        }

        if (response.job_id === null) {
            console.warn('No rules generated. Stopping.')
            return
        }

        getRules(response.message)
    }).fail((xhr, status, error) => {
        let errorMessage = error

        if (xhr.responseJSON !== undefined && xhr.responseJSON.error !== undefined) {
            errorMessage = xhr.responseJSON.error
        }

        notify('error', gettext('Error'), errorMessage)
    })
}

function getRules (jobID) {
    let loadingIcon = $('#whitelist-datatable-loading')
    let datatableContainer = $('#whitelist-datatable-container')

    $.ajax({
        type: 'post',
        timeout: 0,
        url: `${get_defender_whitelist}${jobID}`,
    }).done((response) => {
        response = response.message

        if (response.is_done === null || response.is_done === undefined) {
            console.warn('Response job status is null. Stopping.')
            notify('warning', gettext('Warning'), gettext('The generated rule list is empty'))
            loadingIcon.hide()
            datatableContainer.hide()
            return
        }

        if (!response.is_done) {
            setTimeout(() =>  {
                getRules(jobID)
            }, 1000)

            return
        }

        loadingIcon.hide()
        datatableContainer.show()

        let whitelistArray = response.rules

        if (whitelistArray.length <= 0) {
            console.warn('The rule list is empty. Stopping.')
            notify('warning', gettext('Warning'), gettext('The generated rule list is empty'))
            datatableContainer.hide()
            return
        }

        saveToHistory(whitelistArray)
        displayRuleDatatable(whitelistArray)

        let sendWhitelistButton = $('#btn-send-whitelist')
        sendWhitelistButton.off()

        // when we click on this button inside the modal, we send the configured whitelist
        sendWhitelistButton.on('click', (event) => {
            displaySaveBox()
        })
    }).fail((xhr, status, error) => {
        let errorMessage = error

        if (xhr.responseJSON !== undefined && xhr.responseJSON.error !== undefined) {
            errorMessage = xhr.responseJSON.error
        }

        notify('error', gettext('Error'), errorMessage)

        setTimeout(() =>  {
            getRules(jobID)
        }, 1000)
    })
}

// remove inputs in whitelist database
function resetInputs () {
    $('.whitelist-data-hidden').each((index, element) => {
        let jQueryElement = $(element)
        jQueryElement.show()
        jQueryElement.removeClass('whitelist-data-hidden')
    })

    $('.whitelist-datatable-input').remove()

    if (!jQuery.isEmptyObject(inputHistory)) {
        for (const [i, jValue] of Object.entries(inputHistory)) {
          for (const [j, value] of Object.entries(jValue)) {
              $('#whitelist-datatable').dataTable().fnUpdate(value, parseInt(i), parseInt(j))
          }
        }

        saveToHistory($('#whitelist-datatable').DataTable().fnGetData())
    }

    inputHistory = {}
}

// save inputs to history
function saveToInputHistory (i, j, value) {
    if (inputHistory[i] === undefined) inputHistory[i] = {}

    inputHistory[i][j] = value
}

// highlights what matches in the rule
function highlight (string, ruleIDArray) {
    let highlightIndexArray = []

    if (!string || !ruleIDArray) return string

    // first, we compute the indexes of our substrings to be highlighted
    for (const ruleID of ruleIDArray) {
        const pattern = mainRules[ruleID][1]

        if (!pattern) continue

        if (pattern instanceof RegExp) {
            let match

            while ((match = pattern.exec(string)) !== null) {
                highlightIndexArray.push([match.index, match.index + match['0'].length])
            }
        } else {
            let currentIndex = 0
            let to = -1

            while ((to = string.indexOf(pattern, currentIndex)) > -1) {
                currentIndex = to
                to = to + pattern.length
                highlightIndexArray.push([currentIndex, to])
                currentIndex = to
            }
        }
    }

    highlightIndexArray.sort((current, other) => {
        if (current[0] < other[0]) return -1

        return 1
    })

    // then, we highlight
    let toShift = 0

    for (const highlightIndex of highlightIndexArray) {
        const from = highlightIndex[0] + toShift
        const to = highlightIndex[1] + toShift
        const count = to - from
        const toHighlight = string.substr(from, count)
        const highlighted = `<span class="whitelist-highlighted">${toHighlight}</span>`
        toShift += highlighted.length - toHighlight.length

        string = splice(string, from, count, highlighted)
    }

    return string
}

// display the whitelist in a modal
function displayRuleDatatable (whitelistArray) {
    let whitelistDatatable = $('#whitelist-datatable').DataTable({
        select: true,
        bDestroy: true,
        aoColumns: [
            {
                mData: null,
                sTitle: '<input type="checkbox" id="rule-checkbox-all" name="rule-checkbox-all">',
                bSortable: false,
                bSearchable: false
            },
            {
                mData: 'url',
                sTitle: gettext('URL'),
                mRender: (data, type, row) => {
                    if (data instanceof RegExp) {
                        const string = data.toString()
                        return string.substring(1, string.length - 1)
                    } else {
                        data = DOMPurify.sanitize(data)
                    }

                    let dataClasses = 'rule-text-property'

                    if (row.matched === 'url') {
                        //dataClasses += ' rule-matched-property'
                        data = highlight(data, row.ids)
                    }

                    return `<span class="${dataClasses}">${data}</span>`
                }
            },
            {
                mData: 'id',
                sTitle: gettext('Rule ID'),
                mRender: (data, type, row) => {
                    return `<span class="rule-text-property">${data}</span>`
                }
            },
            {
                mData: null,
                sTitle: gettext('Reason'),
                mRender: (data, type, row) => {
                    data = ''

                    for (const ruleID of row.ids) {
                      data += `${mainRules[ruleID][0]}\n`
                    }

                    data = data.replace(/\n$/, '')

                    return `<span class="label label-warning rule-text-property">${data.toUpperCase()}</span>`
                }
            },
            {
                mData: 'zone',
                sTitle: gettext('Zone'),
                mRender: (data, type, row) => {
                    return `<span class="label label-warning rule-text-property">${data.toUpperCase()}</span>`
                }
            },
            {
                mData: 'key',
                sTitle: gettext('Key'),
                mRender: (data, type, row) => {
                    if (data instanceof RegExp) {
                        const string = data.toString()
                        return string.substring(1, string.length - 1)
                    } else {
                        data = DOMPurify.sanitize(data)
                    }

                    let dataClasses = 'rule-text-property'

                    if (row.matched === 'key') {
                        data = highlight(data, row.ids)
                        //dataClasses += ' rule-matched-property'
                    }

                    return `<span class="${dataClasses}">${data}</span>`
                }
            },
            {
                mData: 'value',
                sTitle: gettext('Value'),
                mRender: (data, type, row) => {
                    if (data instanceof RegExp) {
                        const string = data.toString()
                        return string.substring(1, string.length - 1)
                    } else {
                        data = DOMPurify.sanitize(data)
                    }

                    console.log(row.matched)

                    let dataClasses = 'rule-text-property'

                    if (row.matched === 'value') {
                        data = highlight(data, row.ids)
                        //dataClasses += ' rule-matched-property'
                    }

                    return `<span class="${dataClasses}">${data}</span>`
                }
            }
        ],
        aaData: whitelistArray,
        fnCreatedRow: (nRow, aData, iDataIndex) => {
            const id = `rule-checkbox-${iDataIndex}`

            $('td:eq(0)', nRow).html(`<input class="rule-checkbox" type="checkbox" id="${id}" name="${id}">`)
        },
        fnRowCallback: (nRow, aData, iDisplayIndex, iDisplayIndexFull) => {
             // url
            $($(nRow).children()[1]).on('click', function (event) {
                event.stopPropagation()

                if ($(this).find('input').length > 0) return

                resetInputs()

                let element = $($(this).children()[0])
                element.addClass('whitelist-data-hidden')
                element.hide()

                let inputElement = $('<div class="whitelist-datatable-input"></div>').append(
                    `<input type="text" value="${aData.url}">`
                )

                $(this).append(inputElement)

                inputElement.children().on('input', function (event) {
                    saveToInputHistory(iDisplayIndex, 1, $(this).val())
                })
            })

            // key
            $($(nRow).children()[5]).on('click', function (event) {
                event.stopPropagation()

                if ($(this).find('input').length > 0) return

                resetInputs()

                let element = $($(this).children()[0])
                element.addClass('whitelist-data-hidden')
                element.hide()

                let key = aData.key

                if (!key) key = ''

                let inputElement = $('<div class="whitelist-datatable-input"></div>').append(
                    `<input type="text" value="${key}">`
                )

                $(this).append(inputElement)

                inputElement.children().on('input', function (event) {
                    saveToInputHistory(iDisplayIndex, 5, $(this).val())
                })
            })

            // value
            $($(nRow).children()[6]).on('click', function (event) {
                event.stopPropagation()

                if ($(this).find('input').length > 0) return

                resetInputs()

                let element = $($(this).children()[0])
                element.addClass('whitelist-data-hidden')
                element.hide()

                let value = aData.value

                if (!value) value = ''

                let inputElement = $('<div class="whitelist-datatable-input"></div>').append(
                    `<input type="text" value="${value}">`
                )

                $(this).append(inputElement)

                inputElement.children().on('input', function (event) {
                    saveToInputHistory(iDisplayIndex, 6, $(this).val())
                })
            })
        }
    })

    $('#modal-whitelist-content').off()

    $('#modal-whitelist-content').on('click', function (event) {
        resetInputs()
    })

    $('#modal-whitelist').modal({
        backdrop: 'static',
        keyboard: false
    })

    let ruleCheckboxes = $('.rule-checkbox')

    $('#rule-checkbox-all').prop('checked', false)
    ruleCheckboxes.off()

    ruleCheckboxes.on('change', function (event) {
        if (!$(this).prop('checked')) {
            $('#rule-checkbox-all').prop('checked', false)
        } else {
            if ($('.rule-checkbox:checked').length === ruleCheckboxes.length) {
                $('#rule-checkbox-all').prop('checked', true)
            }
        }
    })
}

// send the configured whitelist
function sendWhitelist () {
    const currentData = $('#whitelist-datatable').DataTable().fnGetData()
    let toSendArray = []

    for (let index = 0; index < currentData.length; ++index) {
        if (!$(`#rule-checkbox-${index}`).prop('checked')) continue

        const element = currentData[index]
        let urlToSend = element.url
        let isRegexUrl = urlToSend instanceof RegExp

        if (isRegexUrl) {
            urlToSend = urlToSend.toString()
            urlToSend = urlToSend.substring(1, urlToSend.length - 1)
        }

        toSendArray.push({
            zone: element.zone,
            key: element.key instanceof RegExp ? `r(${element.key})` : element.key,
            value: element.value instanceof RegExp ? `r(${element.value})` : element.value,
            url: isRegexUrl ? `r(${urlToSend})` : urlToSend,
            ids: element.id,
            matched_type: element.matched
        })
    }

    if (toSendArray.length <= 0) {
        const errorMessage = 'No rules to send'
        console.error(errorMessage)
        notify('error', gettext('Error'), errorMessage)
        console.error(`Something wrong happened: "${errorMessage}". Stopping.`)

        return
    }

    let data = { rules: JSON.stringify(toSendArray), save_type: $('#save-whitelist-type').val() }

    if (data.save_type === 'create') {
        data.name = $('#whitelist-name').val()
    } else {
        data.ruleset_id = parseInt($('#existing-ruleset').val())
    }

    $('#whitelist-datatable-loading').show()
    $('#whitelist-datatable-container').hide()

    $.ajax({
        url: submit_defender_whitelist,
        type: 'post',
        timeout: 0,
        data: data
    }).done((response) => {
        if (!check_json_error(response)) {
            console.error(`Something wrong happened: "${response.error}". Please check logs. Stopping.`)
            return
        }

        notify('success', gettext('Success'), response.message)
        $('#modal-whitelist').modal('hide')
    }).fail((xhr, status, error) => {
        let errorMessage = error

        if (xhr.responseJSON !== undefined && xhr.responseJSON.error !== undefined) {
            errorMessage = xhr.responseJSON.error
        }

        notify('error', gettext('Error'), errorMessage)

        $('#whitelist-datatable-loading').hide()
        $('#whitelist-datatable-container').show()
    })
}

// display relevant inputs for the savebox
function displaySaveInputs () {
    let value = $('#save-whitelist-type').val()
    let whitelistNameContainer = $('.whitelist-name-container')
    let existingRulesetContainer = $('.existing-ruleset-container')
    whitelistNameContainer.hide()
    existingRulesetContainer.hide()

    if (value === 'create') {
        whitelistNameContainer.show()
    } else {
        existingRulesetContainer.show()
    }
}

// display a save box to send the whitelist
function displaySaveBox () {
    $('.whitelist-overlay-save-dialog').show()
    $('.whitelist-rules-content').hide()
    displaySaveInputs()
}
///////////////////////////////////////////////////////////////////////////////

$(document).ready(() => {
    // empty modal content on close
    $('#modal-whitelist').on('hidden.bs.modal', () => {
        $('#modal-whitelist-body').html('')
    })

    // when we click on this button, we display the whitelist in a modal
    $('#btn-defender').on('click', generateAndDisplayRuleDatatable)

    $('#btn-merge-whitelist-datatable').on('click', mergeRules)

    $('#btn-reset-whitelist-datatable').on('click', resetRuleDatatable)

    $('#modal-whitelist').on('change', '#rule-checkbox-all', (event) => {
        $('.rule-checkbox').prop('checked', $('#rule-checkbox-all').prop('checked'))
    })

    setHistoryIndex(0)

    $('#btn-previous-whitelist-datatable').on('click', (event) => {
        restoreHistory(currentHistoryIndex - 1)
    })

    $('#btn-next-whitelist-datatable').on('click', (event) => {
        restoreHistory(currentHistoryIndex + 1)
    })

    $('#cancel-btn-send-whitelist').on('click', (event) => {
        $('.whitelist-overlay-save-dialog').hide()
        $('.whitelist-rules-content').show()
    })

    $('#existing-ruleset').select2({
        ajax: {
            url: get_defender_rulesets,
            allowClear: true,
            placeholder: {
              id: -1,
              text: 'Select a Defender ruleset',
              selected: 'selected'
            },
            delay: 100,
            data: (params) => {
                return {
                    search: params.term,
                    page: params.page || 0
                }
            },
            processResults: (data) => {
                return {
                    results: data.results,
                    pagination: {
                        more: data.pagination.more
                    }
                }
            }
        }
    })

    $('#save-whitelist-type').on('change', function (event) {
        displaySaveInputs()
    })

    $('#rule-checkbox-all').prop('checked', false)

    $('#modal-whitelist').on('hidden.bs.modal', () => {
        $('.whitelist-overlay-save-dialog').hide()
        $('.whitelist-rules-content').show()
    })

    $('#confirm-btn-send-whitelist').on('click', sendWhitelist)
})
