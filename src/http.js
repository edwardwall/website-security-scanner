const GENERIC = require("./generic.js");


/**
 * Check Content-Security-Policy header.
 * @param {string} header
 * @returns {ResultPolicy}
 */
function contentSecurityPolicy(header) {

    if (undefined === header) {
        return {
            result:false,
            data:{}
        }
    }

    let data = GENERIC.parsePolicy(header);

    const UNSAFE = [
        "data: ",

        "http: ",
        "https: ",
        "http://* ",
        "https://* ",

        "'unsafe-eval'",
        "'unsafe-hashes'",
        "'unsafe-inline'",
    ];

    let defaultSrc = data["default-src"];
    let scriptSrc = data["script-src"];
    let styleSrc = data["style-src"];

    // No protection
    if (!defaultSrc &&
        !(scriptSrc && styleSrc)) {

        return {
            result:false,
            data
        }
    }

    let check = [];

    if (scriptSrc) {
        check.push(scriptSrc);
    }
    if (styleSrc) {
        check.push(styleSrc);
    }
    if (2 > check.length) {
        check.push(defaultSrc);
    }

    for (directive of check) {
        for (origin of directive) {

            if (undefined === origin) {
                continue;
            }

            origin += " ";

            for (source of UNSAFE) {
                if (origin.includes(source)) {
                    return {
                        result:false,
                        data
                    };
                }
            }

        }
    }

    return {
        result:true,
        data
    };

}


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
 * Check Feature-Policy header.
 * @param {string} header
 * @returns {ResultPolicy}
 */
function featurePolicy(header) {

    if (undefined === header) {
        return {
            result:false,
            data:{}
        }
    }

    let data = GENERIC.parsePolicy(header);

    const DIRECTIVES = [
        "camera",
        "display-capture",
        "geolocation",
        "microphone",
        "payment"
    ];

    let safe = true;

    for (directive of DIRECTIVES) {

        if (undefined === data[directive]) {
            continue;
        }

        for (elem of data[directive]) {

            elem = elem.trim();

            if ("*" === elem || elem.startsWith("http:")) {
                safe = false;
                break;
            }
        }
    }

    return {
        result:safe,
        data
    };
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
        directive = directive.trim();

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


/**
 * Check miscellaneous headers.
 * @param {Object[]} chain
 * @returns {Object}
 */
function miscellaneousHeaders(chain) {

    let asp = [];
    let server = [];
    let powered = [];

    for (headers of chain) {

        if (headers["x-aspnet-version"]) {
            asp.push(headers["x-aspnet-version"]);
        }
        if (headers["x-aspnetmvc-version"]) {
            asp.push(headers["x-aspnetmvc-version"]);
        }

        if (headers["server"]) {
            server.push(headers["server"]);
        }

        if (headers["x-powered-by"]) {
            powered.push(headers["x-powered-by"]);
        }

    }

    asp = asp.map(e => e.trim());
    server = server.map(e => e.trim());
    powered = powered.map(e => e.trim());

    return {
        asp: getLongest(asp),
        server: getLongest(server),
        powered: getLongest(powered)
    };

    function getLongest(arr) {

        if (0 === arr.length) {
            return GENERIC.VALID_RESULT;
        }

        let longest = "";

        for (elem of arr) {
            if (elem.length > longest.length) {
                longest = elem;
            }
        }

        if (0 === longest.length) {
            return GENERIC.VALID_RESULT;
        } else {
            return {
                result:false,
                data:{
                    value:longest
                }
            };
        }

    }

}


module.exports = {
    contentSecurityPolicy,
    referrerPolicy,
    featurePolicy,
    xContentTypeOptions,
    xFrameOptions,
    xXssProtectionHeader,
    miscellaneousHeaders
}
