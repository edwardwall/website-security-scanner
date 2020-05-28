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

        let chain;

        Promise.allSettled([
            followChain("http:", this.domain),
            followChain("https:",this.domain)

        ]).then(([http, https]) => {

            if ("rejected" === http.status &&
                "rejected" === https.status) {

                throw Error("Both promises rejected.");

            } else if ("rejected" === http.status) {
                chain = https.value;

            } else if ("rejected" === https.status) {
                chain = http.value;

            } else { // Both fulfilled
                chain = http.value; // use HTTP as default
            }

        }).then(() => {

            /* HTTPS */

            let requests = chain.map(e => e.request);

            this.results.upgradeToHttps =
                TEST.HTTPS.upgradeToHttps(requests);

            this.results.secureRedirectionChain =
                TEST.HTTPS.secureRedirectionChain(requests);

            this.results.HSTS =
                TEST.HTTPS.httpStrictTransportSecurity(
                    chain[chain.length - 1].headers["strict-transport-security"]);

            this.results.certificate =
                TEST.HTTPS.certificateValidity(
                    chain[chain.length - 1].certificate);

        })

    }

}

module.exports = WebsiteSecurityScanner;


function followChain(protocol, hostname) {

    return new Promise((resolve, reject) => {

        let options = {
            protocol,
            hostname,
            path: "/"
        };

        let data = {
            chainLength: 0,
            cookies: {}
        };

        let chain = [];

        let callback = (result) => {
            if (undefined === result) {
                reject();
            }

            chain.push(result);
            if (300 > result.status) {
                resolve(chain);
            }
        }

        request(options, data, callback);

    });

}



async function request(options, data, callback) {

    options.agent = false;
    options.headers = {};

    data.chainLength += 1;
    if (8 < data.chainLength) {
        throw Error("Too many redirects - " + options.hostname);
    }

    let cookies = [];
    for (key in data.cookies) {
        cookies.push(key + "=" + data.cookies[key]);
    }

    options.headers.cookies = cookies.join("; ");
    options.headers["user-agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.61 Safari/537.36";

    ("https:" === options.protocol ? NODE.HTTPS : NODE.HTTP).get(options, (res) => {

        let location;
        try {
            location = res.headers.location;
        } catch (e) {}

        if (undefined === location) {
            location = "";
        }

        let status = res.statusCode;

        if (300 > status) { // Success

            let body = "";
            let certificate = res.socket.getPeerCertificate();

            res.on("data", (chunk) => {
                body += chunk.toString();
            });

            res.on("end", () => {
                callback({
                    status,
                    request: options,
                    headers: res.headers,
                    certificate,
                    body
                });
            });

        } else if (400 > status) { // Redirect

            callback({
                status,
                request: options,
                headers: res.header
            });

            location = parseLocation(location, options);
            location = NODE.URL.parse(location);

            let nextOptions = {
                protocol: location.protocol,
                hostname: location.hostname,
                path: location.path
            };

            request(nextOptions, data, callback);

        } else { // Error

            callback(undefined);

        }

    }).on("error", (err) => {
        callback(undefined);
    });

}


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
