/**
 * Test whether the server immediately upgrades to HTTPS.
 *
 * @param {URL[]} chain
 */
function upgradeToHttps(chain) {

    if (2 > chain.length) {
        return false; // chain must be at least 2 elements long
    }

    if ("https:" === chain[0].protocol) {
        throw "First URL should be HTTP";
    }

    return ("https:" === chain[1].protocol);

}


/**
 * Test whether the server maintains a secure connection.
 *
 * @param {URL[]} chain
 */
function secureRedirectionChain(chain) {

    if ("http:" === chain[0].protocol) {
        throw "First URL should be HTTPS";
    }

    let secure = true;

    for (url of chain) {

        if ("https:" != url.protocol) {
            secure = false;
        }

    }

    return secure;

}


/**
 * Test for HTTP Strict Transport Security header.
 *
 * @param {string} header
 */
function httpStrictTransportSecurity(header) {

    const INVALID = {valid:false};

    if (undefined === header) {
        return INVALID;
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
        return INVALID;
    }

    return {
        valid:true,
        result:{
            age,
            includeSubdomains,
            preload
        }
    };

}


module.exports = {
    upgradeToHttps,
    secureRedirectionChain,
    httpStrictTransportSecurity
};
