const NODE = {
    URL: require("url")
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

        Promise.all([
            TEST.DNS.caa(this.domain, (result) => {
                this.results.CAA = result;
            }),
            TEST.DNS.dnssec(this.domain, (result) => {
                this.results.DNSSEC = result;
            })
        ]).then(() => {

        });

    }

}

module.exports = WebsiteSecurityScanner;
