const DNS = require("../src/dns.js");
const GENERIC = require("../src/generic.js");


describe("Check caa()", () => {

    test("valid", () => {

        expect(DNS.caa("bankgradesecurity.com"))
            .resolves.toEqual(GENERIC.VALID_RESULT);

    });

    test("invalid", () => {

        expect(DNS.caa("example.com"))
            .resolves.toEqual(GENERIC.INVALID_RESULT);

    });

});


describe("Check dnssec()", () => {

    test("valid", () => {

        expect(DNS.dnssec("example.com"))
            .resolves.toEqual(GENERIC.VALID_RESULT);

    });

    test("invalid", () => {

        expect(DNS.dnssec("nodnssec.example.com"))
            .resolves.toEqual(GENERIC.INVALID_RESULT);

    });

});
