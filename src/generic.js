const HTTPS = require("https")

const INVALID_RESULT = {result:false};
const VALID_RESULT   = {result:true};


async function get(url, callback) {

    HTTPS.get(url, (res) => {

        let body = "";

        res.on("data", (chunk) => {
            body += chunk.toString();
        });

        res.on("end", () => {
            callback(res.headers, body);
        });

    }).on("error", (err) => {
        callback(err);
    });

}


/**
 * Search through header for properly formed key=value pair.
 *
 * @param {string} header
 * @param {string} key
 * @param {string} value
 */
function checkHeaderKeyValue(header, key, value) {

    key = key.toLowerCase();
    value = value.toLowerCase();

    header = header.toLowerCase().split(";");
    let found = false;

    for (directive of header) {

        directive = directive.trim();

        if (!directive.startsWith(key)) {
            continue;
        }
        directive = directive.substring(key.length).trim();

        if (!directive.startsWith("=")) {
            continue;
        }
        directive = directive.substring("=".length).trim() + " ";

        if (directive.startsWith(value + " ")) {
            found = true;
        }

    }

    return found;

}


/**
 * Parse a policy (CSP or Feature).
 *
 * @param {string} policy
 */
function parsePolicy(policy) {

    if (undefined === policy) {
        throw "Policy is undefined";
    }

    let result = {};

    for (section of policy.toLowerCase().split(";")) {

        section = section.trim();

        let directive = section.substring(0, section.indexOf(" "));
        section = section.substring(section.indexOf(" ") + 1);

        result[directive] = section.split(" ");

    }

    return result;

}


module.exports = {
    INVALID_RESULT,
    VALID_RESULT,
    get,
    checkHeaderKeyValue,
    parsePolicy
};
