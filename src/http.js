const GENERIC = require("./generic.js");


/**
 * Check Referrer-Policy header.
 */
function referrerPolicy(header) {

    if (undefined === header) {
        return GENERIC.INVALID_RESULT;
    }

    header = header.toLowerCase().trim();

    const REFERRERS = [
        "no-referrer",
        "origin",
        "origin-when-cross-origin",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin"
    ];

    /*
        "no-referrer-when-downgraded" and "unsafe-url"
        are excluded as they allow full referrer to other origins
    */

    for (ref of REFERRERS) {
        if (ref === header) {
            return GENERIC.VALID_RESULT;
        }
    }

    return GENERIC.INVALID_RESULT;

}


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
 * Check X-Frame-Options header.
 */
function xFrameOptions(header) {

    if (undefined == header) {
        return GENERIC.INVALID_RESULT;
    }

    header = header.toLowerCase().trim();
    let valid = false;

    for (directive of header.split(";")) {
        if ("deny" === directive ||
            "sameorigin" === directive) {

            valid = true;
        }
    }

    if (valid) {
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

    if (undefined === header) {
        return GENERIC.INVALID_RESULT;
    }

    header = header.toLowerCase();
    let valid = false;

    for (directive of header.split(";")) {
        if ("1" === directive.trim()) {
            valid = true;
        }
    }

    if (!valid) {
        return GENERIC.INVALID_RESULT;
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
    xFrameOptions,
    xXssProtectionHeader
}
