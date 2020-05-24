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

    header = header.split(";");

    let age = 0;

    for (i = 0; i < header.length; i++) {

        let directive = header[i];

        if (directive.includes("max-age") &&
            directive.replace(/ /g, "").startsWith("max-age=")) {

            age = directive.substring(directive.indexOf("=") + 1);
            age = parseInt(age);

        }

    }

    if (!(0 < age)) {
        return INVALID;
    }

    return {
        valid:true,
        result:{
            age
        }
    };

}


module.exports = {
    upgradeToHttps,
    secureRedirectionChain,
    httpStrictTransportSecurity
};
