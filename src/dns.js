const GENERIC = require("./generic.js")


/**
 * Check DNS Certification Authority Authorization (CAA).
 * @param {string} domain
 * @returns {Result}
 */
async function caa(domain) {

    return new Promise((resolve, reject) => {

        let callback = (body) => {
            body = JSON.parse(body);

            if (body.Answer) {
                resolve(GENERIC.VALID_RESULT);
            } else {
                resolve(GENERIC.INVALID_RESULT);
            }
        }

        GENERIC.get(
            "https://dns.google.com/resolve?type=CAA&dnssec=true&name=" + domain,
            callback
        );

    });

}


/**
 * Check DNS Security Extensions (DNSSEC).
 * @param {string} domain
 * @returns {Result}
 */
async function dnssec(domain, callback) {

    return new Promise((resolve, reject) => {

        let callback = (body) => {
            body = JSON.parse(body);

            if (body.Answer) {
                resolve(GENERIC.VALID_RESULT);
            } else {
                resolve(GENERIC.INVALID_RESULT);
            }
        }

        GENERIC.get(
            "https://dns.google.com/resolve?type=DS&dnssec=true&name=" + domain,
            callback
        );

    });

}


module.exports = {
    caa,
    dnssec
}
