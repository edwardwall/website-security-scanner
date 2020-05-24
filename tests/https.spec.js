const HTTPS = require("../src/https.js")
const GENERIC = require("../src/generic.js");


describe("Check upgradeToHttps()", () => {

    test("chain too short", () => {

        expect(
            HTTPS.upgradeToHttps([])
        ).toBe(GENERIC.INVALID_RESULT);

        expect(
            HTTPS.upgradeToHttps([{protocol:"http:"}])
        ).toBe(GENERIC.INVALID_RESULT);

    });

    test("connection is not upgraded", () => {

        const INPUT = [
            {protocol:"http:"},
            {protocol:"http:"}
        ];

        expect(HTTPS.upgradeToHttps(INPUT)).toBe(GENERIC.INVALID_RESULT);

    });

    test("connection is upgraded", () => {

        const INPUT = [
            {protocol:"http:"},
            {protocol:"https:"}
        ];

        expect(HTTPS.upgradeToHttps(INPUT)).toBe(GENERIC.VALID_RESULT);

    });

    test("initial connection is https", () => {

        expect(() => {
            HTTPS.upgradeToHttps([
                {protocol:"https:"},
                {protocol:"http:"}
            ])
        }).toThrow();

        expect(() => {
            HTTPS.upgradeToHttps([
                {protocol:"https:"},
                {protocol:"https:"}
            ])
        }).toThrow();

    });

});


describe("Check secureRedirectionChain()", () => {

    test("initial connection is http", () => {

        expect(() => {
            HTTPS.secureRedirectionChain([
                {protocol:"http:"},
                {protocol:"http:"}
            ])
        }).toThrow();

        expect(() => {
            HTTPS.secureRedirectionChain([
                {protocol:"http:"},
                {protocol:"https:"}
            ])
        }).toThrow();

    });

    test("identify whether chain is secure", () => {

        expect(HTTPS.secureRedirectionChain([
            {protocol:"https:"},
            {protocol:"http:"},
            {protocol:"http:"}
        ])).toBe(GENERIC.INVALID_RESULT);

        expect(HTTPS.secureRedirectionChain([
            {protocol:"https:"},
            {protocol:"https:"},
            {protocol:"http:"}
        ])).toBe(GENERIC.INVALID_RESULT);

        expect(HTTPS.secureRedirectionChain([
            {protocol:"https:"},
            {protocol:"http:"},
            {protocol:"https:"}
        ])).toBe(GENERIC.INVALID_RESULT);

        expect(HTTPS.secureRedirectionChain([
            {protocol:"https:"},
            {protocol:"https:"},
            {protocol:"https:"}
        ])).toBe(GENERIC.VALID_RESULT);

    });

});


describe("Check httpStrictTransportSecurity()", () => {

    test("invalid headers", () => {

        expect(
            HTTPS.httpStrictTransportSecurity("max-age=0")
        ).toEqual(GENERIC.INVALID_RESULT);

        expect(
            HTTPS.httpStrictTransportSecurity("max-age = 0")
        ).toEqual(GENERIC.INVALID_RESULT);

        expect(
            HTTPS.httpStrictTransportSecurity("max -age=1000")
        ).toEqual(GENERIC.INVALID_RESULT);

        expect(
            HTTPS.httpStrictTransportSecurity("max-age=-1000")
        ).toEqual(GENERIC.INVALID_RESULT);

        expect(
            HTTPS.httpStrictTransportSecurity("strict-transport-security: max-age=1000")
        ).toEqual(GENERIC.INVALID_RESULT);

        expect(
            HTTPS.httpStrictTransportSecurity("1")
        ).toEqual(GENERIC.INVALID_RESULT);

        expect(
            HTTPS.httpStrictTransportSecurity("true")
        ).toEqual(GENERIC.INVALID_RESULT);

        expect(
            HTTPS.httpStrictTransportSecurity("")
        ).toEqual(GENERIC.INVALID_RESULT);

        expect(
            HTTPS.httpStrictTransportSecurity(undefined)
        ).toEqual(GENERIC.INVALID_RESULT);

    });

    test("valid headers", () => {

        expect(
            HTTPS.httpStrictTransportSecurity("max-age=1000  ; includeSubdomains;")
        ).toEqual({
            result:true,
            data:{
                age:1000,
                includeSubdomains: true,
                preload: false
            }
        });

        expect(
            HTTPS.httpStrictTransportSecurity("max-AGE = 1000 preload")
        ).toEqual({
            result:true,
            data:{
                age:1000,
                includeSubdomains: false,
                preload: false
            }
        });

        expect(
            HTTPS.httpStrictTransportSecurity("max-age=1000000; includeSubdomains;preload")
        ).toEqual({
            result:true,
            data:{
                age:1000000,
                includeSubdomains:true,
                preload:true
            }
        });

        expect(
            HTTPS.httpStrictTransportSecurity("max-age=100 1 ;includeSubdomains-preload")
        ).toEqual({
            result:true,
            data:{
                age:100,
                includeSubdomains:false,
                preload:false
            }
        });

    });

});
