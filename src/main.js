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

const GENERIC = require("./generic.js");


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

        if (0 !== Object.keys(this.results).length) {
            throw Error("Already scanned.");
        }

        return new Promise((resolve, reject) => {

            let chain;
            let last;
            let secondChain = [];

            Promise.allSettled([
                followChain("http:", this.domain),
                followChain("https:",this.domain)

            ]).then(([http, https]) => {

                if ("rejected" === http.status &&
                    "rejected" === https.status) {

                    throw Error(this.domain + " cannot be accessed by HTTP or HTTPS");

                } else if ("rejected" === http.status) {
                    chain = https.value;

                } else if ("rejected" === https.status) {
                    chain = http.value;

                } else { // Both fulfilled
                    chain = http.value; // use HTTP as default
                    secondChain = https.value;
                }

                last = chain[chain.length - 1];

                this.results.accepts = {
                    http: ("fulfilled" === http.status),
                    https:("fulfilled" === https.status)
                }

            }).then(() => {

                /* DNS */

                return Promise.all([
                    TEST.DNS.caa(this.domain),
                    TEST.DNS.dnssec(this.domain)

                ]).then(([caa, dnssec]) => {

                    this.results.caa = caa;
                    this.results.dnssec = dnssec;
                });

            }).then(() => {

                /* TLS */

                this.results.forwardSecrecy = TEST.TLS.forwardSecrecy(last.cipher);

                this.results.certificate =
                    TEST.TLS.certificateValidity(last.certificate);

                return Promise.all([
                    TEST.TLS.checkProtocols(this.domain)

                ]).then(([ps]) => {

                    let result = ps["1.3"] && !ps["1.1"] && !ps["1.0"];

                    this.results.tlsProtocols = {
                        result,
                        data:ps
                    };

                });

            }).then(() => {

                /* HTTPS */

                let requests = chain.map(e => e.request);
                let secondRequests = chain.map(e => e.request);

                this.results.upgradeToHttps =
                    (this.results.accepts.http ?
                        TEST.HTTPS.upgradeToHttps(requests) :
                        GENERIC.INVALID_RESULT
                    );

                this.results.secureRedirectionChain =
                    ((this.results.accepts.http && this.results.accepts.https &&
                    TEST.HTTPS.secureRedirectionChain(requests) &&
                    TEST.HTTPS.secureRedirectionChain(secondRequests)) ?
                        GENERIC.VALID_RESULT :
                        GENERIC.INVALID_RESULT
                    );

                return Promise.all([
                    TEST.HTTPS.httpStrictTransportSecurity(
                        last.headers["strict-transport-security"], this.domain)

                ]).then(([result]) => {
                    this.results.hsts = result;
                });

            }).then(() => {

                /* HTTP */

                this.results.contentSecurityPolicy =
                    TEST.HTTP.contentSecurityPolicy(
                        last.headers["content-security-policy"]);

                this.results.featurePolicy =
                    TEST.HTTP.featurePolicy(
                        last.headers["feature-policy"]);

                this.results.referrerPolicy =
                    TEST.HTTP.referrerPolicy(
                        last.headers["referrer-policy"]);

                this.results.xXssProtection =
                    TEST.HTTP.xXssProtectionHeader(
                        last.headers["x-xss-protection"]);

                this.results.xContentTypeOptions =
                    TEST.HTTP.xContentTypeOptions(
                        last.headers["x-content-type-options"]);

                this.results.xFrameOptions =
                    TEST.HTTP.xFrameOptions(
                        last.headers["x-frame-options"]);

                let headers = chain.map(e => e.headers);
                let miscHeaders = TEST.HTTP.miscellaneousHeaders(headers);

                this.results.server = miscHeaders.server;
                this.results.poweredBy = miscHeaders.powered;
                this.results.aspVersion = miscHeaders.asp;

            }).then(() => {
                resolve(this.results);
            });

        });

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
            } else {
                chain.push(result);
                if (300 > result.status) {
                    resolve(chain);
                }
            }
        }

        request(options, data, callback);

    });

}

async function request(options, data, callback) {

    options.agent = false;
    options.headers = {};
    options.timeout = 10000; // 10 second timeout for request

    data.chainLength += 1;
    if (8 < data.chainLength) {
        throw Error("Too many redirects - " + options.hostname);
    }

    let cookies = [];
    for (key in data.cookies) {
        cookies.push(key + "=" + data.cookies[key]);
    }

    options.headers.cookie = cookies.join("; ");
    options.headers["user-agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.61 Safari/537.36";

    let requestObject = ("https:" === options.protocol ? NODE.HTTPS : NODE.HTTP).get(options, (res) => {

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
            let certificate;
            let cipher;

            if ("https:" === options.protocol) {
                certificate = res.socket.getPeerCertificate();
                cipher = res.socket.getCipher();
            }

            res.on("data", (chunk) => {
                body += chunk.toString();
            });

            res.on("end", () => {
                callback({
                    status,
                    request: options,
                    headers: res.headers,
                    certificate,
                    cipher,
                    body
                });
            });

        } else if (400 > status) { // Redirect

            callback({
                status,
                request: options,
                headers: res.headers
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
    }).on("timeout", () => {
        requestObject.destroy();
        callback(undefined);
    });

}

/**
 * Parse Location header returned in HTTP redirect.
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
