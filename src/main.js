const URL = require("url");


/**
 * Parse Location header returned as HTTP redirect.
 * @param {string} location
 * @param {Object} options
 * @returns {string}
 */
function parseLocation(location, options) {

    let url;

    // Check whether location is fully qualified URL
    url = URL.parse(location);
    if (url.protocol && url.hostname && url.path) {
        return url.href;
    }

    // Check whether location is URL without protocol
    if (location.startsWith("//")) {
        url = URL.parse(options.protocol + location);

        if (url.protocol && url.hostname && url.hostname.includes(".")) {
            if (null === url.path) {
                url.href += "/";
            }
            return url.href;
        }
    }

    if (location.startsWith("/")) {
        location = options.protocol + "//" + options.hostname + location;

    } else {
        location = options.protocol + "//" + options.hostname +
            options.path.substring(0, options.path.lastIndexOf("/") + 1) +
            location;
    }

    url = URL.parse(location);
    return url.href;

}


module.exports = {
    parseLocation
};
