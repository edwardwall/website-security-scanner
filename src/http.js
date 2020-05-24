const GENERIC = require("./generic.js");


/**
 * Check X-Content-Type-Options header.
 *
 * @param {string} header
 */
function xContentTypeOptions(header) {

    if (undefined !== header &&
        "nosniff" === header.toLowerCase().trim()) {

        return GENERIC.VALID_RESULT;
    } else {
        return GENERIC.INVALID_RESULT;
    }

}


/**
 * Check X-XSS-Protection HTTP header.
 *
 * @param {string} header
 */
function xXssProtectionHeader(header) {

    const INVALID = {result:false};

    if (undefined === header) {
        return INVALID;
    }

    header = header.toLowerCase();
    let valid = false;

    for (directive of header.split(";")) {
        if ("1" === directive.trim()) {
            valid = true;
        }
    }

    if (!valid) {
        return INVALID;
    }

    return {
        result: true,
        data:{
            block: GENERIC.checkHeaderKeyValue(header, "mode", "block")
        }
    }

}


module.exports = {
    xContentTypeOptions,
    xXssProtectionHeader
}