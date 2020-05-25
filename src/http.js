const GENERIC = require("./generic.js");


 /**
 * @typedef {Result} ResultReferrerPolicy
 * @property {string} data.value
 */
/**
 * Check Referrer-Policy header.
 * @param {string} header
 * @returns {ResultReferrerPolicy}
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

    // "no-referrer-when-downgraded" and "unsafe-url" excluded
    // because they allow full referrer to other origins

    for (ref of REFERRERS) {
        if (ref === header) {
            return {
                result:true,
                data:{
                    value:header
                }
            };
        }
    }

    return GENERIC.INVALID_RESULT;

}


/**
 * Check X-Content-Type-Options header.
 * @param {string} header
 * @returns {Result}
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
 * @param {string} header
 * @returns {Result}
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
 * @typedef {Result} ResultXssProtection
 * @property {boolean} data.block
 */
/**
 * Check X-XSS-Protection HTTP header.
 * @param {string} header
 * @returns {ResultXssProtection}
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
    referrerPolicy,
    xContentTypeOptions,
    xFrameOptions,
    xXssProtectionHeader
}
