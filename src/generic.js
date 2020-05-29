const URL = require("url");
const HTTPS = require("https");

const INVALID_RESULT = {result:false};
const VALID_RESULT   = {result:true};


/**
 * @typedef {Object} Result
 * @property {boolean} result
 * @property {Object} [data]
 */


/**
 * @typedef {Object} URL
 * @property {string} protocol
 * @property {string} hostname
 * @property {string} path
 * @property {string} href
 */


/**
 * Callback for async tests to store result.
 * @callback CallbackResult
 * @param {Result} result
 */

/**
 * Callback for analysing result from generic get().
 * @callback CallbackAnalyse
 * @param {string} body
 */


/**
 * Function to make a generic HTTPS GET request.
 * @param {string} url
 * @param {CallbackAnalyse} callback
 */
async function get(url, callback) {

    HTTPS.get(url, (res) => {

        let body = "";

        res.on("data", (chunk) => {
            body += chunk.toString();
        });

        res.on("end", () => {
            callback(body);
        });

    }).on("error", (err) => {
        callback(err);
    });

}


/**
 * Search through header for key=value pair.
 * @param {string} header
 * @param {string} key
 * @param {string} value
 * @returns {boolean}
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
 * @typedef {Result} ResultPolicy
 * @property {string[]} data.*
 */
/**
 * Parse a policy (CSP or Feature).
 * @param {string} policy
 * @returns {ResultPolicy}
 */
function parsePolicy(policy) {

    if (undefined === policy) {
        throw "Policy is undefined";
    }

    let result = {};

    for (section of policy.toLowerCase().split(";")) {

        section = section.trim();

        if ("" === section) {
            continue;
        }

        let spaceIndex = section.indexOf(" ");
        if (-1 === spaceIndex) {
            result[section] = [];
            continue;
        }

        let directive = section.substring(0, spaceIndex);
        section = section.substring(spaceIndex + 1);

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
