const GENERIC = require("./generic.js");


/**
 * Test whether the server immediately upgrades to HTTPS.
 * @param {URL[]} chain
 * @returns {Result}
 * @throws If first request is HTTPS
 */
function upgradeToHttps(chain) {

    if (2 > chain.length) {
        return GENERIC.INVALID_RESULT;
    }

    if ("https:" === chain[0].protocol) {
        throw "First URL should be HTTP";
    }

    if ("https:" === chain[1].protocol) {
        return GENERIC.VALID_RESULT;
    } else {
        return GENERIC.INVALID_RESULT;
    }

}


/**
 * Test whether the server redirects through secure connections.
 * @param {URL[]} chain
 * @returns {Result}
 * @throws If chain has 0 elements.
 */
function secureRedirectionChain(chain) {

    if (0 === chain.length) {
        throw Error("Chain cannot be empty.");

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
    } else {
        return GENERIC.INVALID_RESULT;
    }

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
 * @returns {ResultHsts}
 */
function httpStrictTransportSecurity(header) {

    if (undefined === header) {
        return GENERIC.INVALID_RESULT;
    }

    header = header.toLowerCase().split(";");

    let age = 0;
    let includeSubdomains = false;
    let preload = false;

    for (i = 0; i < header.length; i++) {

        let directive = header[i].trim() + " ";

        if (directive.startsWith("max-age") &&
            directive.replace(/ /g, "").startsWith("max-age=")) {

            age = directive.substring(directive.indexOf("=") + 1);
            age = parseInt(age);

        } else if (directive.startsWith("includesubdomains ")) {
            includeSubdomains = true;

        } else if (directive.startsWith("preload ")) {
            preload = true;
        }

    }

    if (!(0 < age)) {
        return GENERIC.INVALID_RESULT;
    }

    return {
        result:true,
        data:{
            age,
            includeSubdomains,
            preload
        }
    };

}


/**
 * @typedef {Result} ResultCertificate
 * @property {number} data.length
 */
/**
 * Check for Certificate validity.
 * @param {Object} certificate
 * @param {ResultCertificate}
 */
function certificateValidity(certificate) {

    if (undefined === certificate) {
        return GENERIC.INVALID_RESULT;
    }

    let start = Date.parse(certificate.valid_from);
    let end   = Date.parse(certificate.valid_to);

    let length = end - start;
    length /= (1000 * 60 * 60 * 24); // covert from miliseconds to days
    length = Math.floor(length);

    return {
        result: (190 >= length), // roughly 6 months
        data:{
            length
        }
    };

}


module.exports = {
    upgradeToHttps,
    secureRedirectionChain,
    httpStrictTransportSecurity,
    certificateValidity
};
