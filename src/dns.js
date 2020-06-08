const GENERIC = require("./generic.js")


/**
 * Check DNS Certification Authority Authorization (CAA).
 * @param {string} domain
 * @returns {Promise}
 */
async function caa(domain) {

    return dnsLookup(domain, "CAA");

}

/**
 * Check DNS Security Extensions (DNSSEC).
 * @param {string} domain
 * @returns {Promise}
 */
async function dnssec(domain) {

    return dnsLookup(domain, "DS");

}

/**
 * Private function to perform DNS lookup.
 * @param {string} domain
 * @param {string} type
 * @returns {Promise}
 */
async function dnsLookup(domain, type) {

    return new Promise((resolve, reject) => {

        let callback = (body) => {
            body = JSON.parse(body);

            if (body.Answer) {
                resolve(GENERIC.VALID_RESULT);
            }
            resolve(GENERIC.INVALID_RESULT);
        }

        let url = "https://dns.google.com/resolve?dnssec=true" +
            "&type=" + type + "&name=" + domain;

        GENERIC.get(url, callback);

    });

}

module.exports = {
    caa,
    dnssec
}
