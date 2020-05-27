const GENERIC = require("./generic.js")


/**
 * Check DNS Certification Authority Authorization (CAA).
 * @param {string} domain
 * @param {CallbackAnalyse} callback
 */
async function caa(domain, callback) {

    let wrappedCallback = (body) => {

        body = JSON.parse(body);

        if (!body.Answer) {
            callback(GENERIC.INVALID_RESULT);
            return;
        }

        let issuer = false;

        for (elem of body.Answer) {

            elem = elem.data;
            elem = elem.substring("0 ".length);
            elem = elem.toLowerCase().trim();

            if (elem.startsWith("issue ") ||
                elem.startsWith("issuewild ")) {

                issuer = true;
            }

        }

        if (issuer) {
            callback(GENERIC.VALID_RESULT);
        } else {
            callback(GENERIC.INVALID_RESULT);
        }

    };

    GENERIC.get(
        "https://dns.google.com/resolve?type=CAA&dnssec=true&name=" + domain,
        wrappedCallback
    );

}


/**
 * Check DNS Secure Extensions (DNSSEC).
 * @param {string} domain
 * @param {CallbackAnalyse} callback
 */
async function dnssec(domain, callback) {

    let wrappedCallback = (body) => {

        body = JSON.parse(body);

        if (body.Answer) {
            callback(GENERIC.VALID_RESULT);
        } else {
            callback(GENERIC.INVALID_RESULT);
        }

    };

    GENERIC.get(
        "https://dns.google.com/resolve?type=DS&dnssec=true&name=" + domain,
        wrappedCallback
    );

}


module.exports = {
    caa,
    dnssec
}
