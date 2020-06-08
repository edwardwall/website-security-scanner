const HTTPS = require("../src/https.js")
const GENERIC = require("../src/generic.js");


describe("Check upgradeToHttps()", () => {

    test("connection is not upgraded", () => {

        expect(HTTPS.upgradeToHttps([]))
            .toBe(GENERIC.INVALID_RESULT);

        expect(HTTPS.upgradeToHttps([
            {protocol:"http:"},
            {protocol:"http:"}
        ])).toBe(GENERIC.INVALID_RESULT);

    });

    test("connection is upgraded", () => {

        expect(HTTPS.upgradeToHttps([
            {protocol:"http:"},
            {protocol:"https:"}
        ])).toBe(GENERIC.VALID_RESULT);

    });

    test("initial connection is https", () => {

        expect(() => {
            HTTPS.upgradeToHttps([
                {protocol:"https:"},
                {protocol:"https:"}
            ])
        }).toThrow();

    });

});


describe("Check secureRedirectionChain()", () => {

    test("not upgraded", () => {

        expect(HTTPS.secureRedirectionChain([]))
            .toBe(GENERIC.INVALID_RESULT);

        expect(HTTPS.secureRedirectionChain([{protocol:"http:"}]))
            .toEqual(GENERIC.INVALID_RESULT);

        expect(HTTPS.secureRedirectionChain([
            {protocol:"https:"},
            {protocol:"http:"},
            {protocol:"https:"}
        ])).toBe(GENERIC.INVALID_RESULT);

        expect(HTTPS.secureRedirectionChain([
            {protocol:"https:"},
            {protocol:"https:"},
            {protocol:"http:"}
        ])).toBe(GENERIC.INVALID_RESULT);

    });

    test("upgraded", () => {

        expect(HTTPS.secureRedirectionChain([
            {protocol:"https:"}
        ])).toEqual(GENERIC.VALID_RESULT);

        expect(HTTPS.secureRedirectionChain([
            {protocol:"https:"},
            {protocol:"https:"}
        ])).toBe(GENERIC.VALID_RESULT);

        expect(HTTPS.secureRedirectionChain([
            {protocol:"http:"},
            {protocol:"https:"}
        ])).toBe(GENERIC.VALID_RESULT);

    });

});


describe("Check httpStrictTransportSecurity()", () => {

    test("invalid headers", () => {

        expect(HTTPS.httpStrictTransportSecurity(undefined))
            .toEqual(GENERIC.INVALID_RESULT);

        expect(HTTPS.httpStrictTransportSecurity("max-age = 0"))
            .toEqual(GENERIC.INVALID_RESULT);

        expect(HTTPS.httpStrictTransportSecurity("max-age=-1000"))
            .toEqual(GENERIC.INVALID_RESULT);

    });

    test("valid headers", () => {

        expect(
            HTTPS.httpStrictTransportSecurity("MAX-AGE=1000000  ; includeSubdomains;")
        ).resolves.toEqual({
            result:true,
            data:{
                age:11,
                includeSubdomains:true,
                preload:false,
                preloaded:false
            }
        });

        expect(
            HTTPS.httpStrictTransportSecurity("max-age=31536000; includeSubdomains; preload", "hstspreload.org")
        ).resolves.toEqual({
            result:true,
            data:{
                age:365,
                includeSubdomains:true,
                preload:true,
                preloaded:true
            }
        });

    });

});
