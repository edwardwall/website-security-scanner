const GENERIC = require("./generic.js");


/**
 * Test whether the server immediately upgrades to HTTPS.
 * @param {URL[]} chain
 * @returns {Result}
 * @throws If first request is HTTPS.
 */
function upgradeToHttps(chain) {

    if (2 > chain.length) {
        return GENERIC.INVALID_RESULT;
    }

    if ("https:" === chain[0].protocol) {
        throw Error("First URL should be HTTP");
    }

    if ("https:" === chain[1].protocol) {
        return GENERIC.VALID_RESULT;
    }

    return GENERIC.INVALID_RESULT;

}

/**
 * Test whether the server redirects through secure connections.
 * @param {URL[]} chain
 * @returns {Result}
 * @throws If chain has 0 elements.
 */
function secureRedirectionChain(chain) {

    if (0 === chain.length) {
        return GENERIC.INVALID_RESULT;
    } else if (1 === chain.length) {
        // Do nothing.
    } else {
        chain.shift(); // Remove first element.
    }

    let secure = true;

    for (url of chain) {
        if ("https:" !== url.protocol) {
            secure = false;
        }
    }

    if (secure) {
        return GENERIC.VALID_RESULT;
    }

    return GENERIC.INVALID_RESULT;

}

/**
 * @typedef {Result} ResultHsts
 * @property {number} data.age
 * @property {boolean} data.includeSubdomains
 * @property {boolean} data.preload
 */
/**
 * Test for HTTP Strict Transport Security header.
 * @param {string} header
 * @param {string} domain
 * @returns {Result|Promise}
 */
function httpStrictTransportSecurity(header, domain) {

    if (undefined === header) {
        return GENERIC.INVALID_RESULT;
    }

    header = header.toLowerCase().split(";");

    let age = 0;
    let includeSubdomains = false;
    let preload = false;

    for (directive of header) {

        directive = directive.trim() + " ";

        if (directive.startsWith("max-age") &&
            directive.replace(/ /g, "").startsWith("max-age=")) {

            age = directive.substring(directive.indexOf("=") + 1);
            age = parseInt(age);
            age = GENERIC.secondsToDays(age);

        } else if (directive.startsWith("includesubdomains ")) {
            includeSubdomains = true;

        } else if (directive.startsWith("preload ")) {
            preload = true;
        }

    }

    if (!(0 < age)) {
        return GENERIC.INVALID_RESULT;
    }

    return new Promise((resolve, reject) => {

        let callback = (body) => {
            body = JSON.parse(body);

            resolve({
                result:true,
                data:{
                    age,
                    includeSubdomains,
                    preload,
                    preloaded:("preloaded" === body.status)
                }
            });
        }

        if (includeSubdomains && preload && (age >= 365)) {
            GENERIC.get("https://hstspreload.org/api/v2/status?domain=" + domain, callback);

        } else {
            callback("{}"); // preloaded will be set to false
        }

    });

}

module.exports = {
    upgradeToHttps,
    secureRedirectionChain,
    httpStrictTransportSecurity
};
