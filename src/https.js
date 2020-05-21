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


module.exports = {
    upgradeToHttps
};
