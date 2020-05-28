const NODE = {
    URL: require("url"),
    HTTP: require("http"),
    HTTPS: require("https")
};

const TEST = {
    DNS: require("./dns.js"),
    TLS: require("./tls.js"),
    HTTP: require("./http.js"),
    HTTPS: require("./https.js")
};


class WebsiteSecurityScanner {

    /**
     * Scanner.
     * @constructor
     * @param {string} domain
     */
    constructor(domain) {

        if (undefined === domain) {
            throw Error("Must specify domain WebsiteSecurityScanner('example.com')");
        }

        if (domain === NODE.URL.parse("https://" + domain).hostname &&
            domain.includes(".")) {

            this.domain = domain;
            this.results = {};

        } else {
            throw Error("Must specify valid root domain, eg example.com");
        }

    }

    /**
     * Function to return the domain.
     * @return {string}
     */
    getDomain() {
        return this.domain;
    }

    /**
     * Function to return the results.
     * @return {Object}
     */
    getResults() {
        return this.results;
    }

    /**
     * Function to perform scanning.
     */
    scan() {

    }

}

module.exports = WebsiteSecurityScanner;


/**
 * Parse Location header returned as HTTP redirect.
 * @param {string} location
 * @param {Object} options
 * @returns {string}
 */
function parseLocation(location, options) {

    let url;

    // Check whether location is fully qualified URL
    url = NODE.URL.parse(location);
    if (url.protocol && url.hostname && url.path) {
        return url.href;
    }

    // Check whether location is URL without protocol
    if (location.startsWith("//")) {
        url = NODE.URL.parse(options.protocol + location);

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

    url = NODE.URL.parse(location);
    return url.href;

}
