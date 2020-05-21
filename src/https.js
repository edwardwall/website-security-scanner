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


module.exports = {
    upgradeToHttps,
    secureRedirectionChain
};
