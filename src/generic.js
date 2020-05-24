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


module.exports = {
    INVALID_RESULT,
    VALID_RESULT,
    get,
    checkHeaderKeyValue
};
