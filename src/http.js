const GENERIC = require("./generic.js");


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
    xXssProtectionHeader
}
