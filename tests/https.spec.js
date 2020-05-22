const HTTPS = require("../src/https.js")

describe("Check upgradeToHttps()", () => {

    test("chain too short", () => {

        expect(
            HTTPS.upgradeToHttps([])
        ).toBe(false);

        expect(
            HTTPS.upgradeToHttps([{protocol:"http:"}])
        ).toBe(false);

    });

    test("connection is not upgraded", () => {

        const INPUT = [
            {protocol:"http:"},
            {protocol:"http:"}
        ];

        expect(HTTPS.upgradeToHttps(INPUT)).toBe(false);

    });

    test("connection is upgraded", () => {

        const INPUT = [
            {protocol:"http:"},
            {protocol:"https:"}
        ];

        expect(HTTPS.upgradeToHttps(INPUT)).toBe(true);

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
        ])).toBe(false);

        expect(HTTPS.secureRedirectionChain([
            {protocol:"https:"},
            {protocol:"https:"},
            {protocol:"http:"}
        ])).toBe(false);

        expect(HTTPS.secureRedirectionChain([
            {protocol:"https:"},
            {protocol:"http:"},
            {protocol:"https:"}
        ])).toBe(false);

        expect(HTTPS.secureRedirectionChain([
            {protocol:"https:"},
            {protocol:"https:"},
            {protocol:"https:"}
        ])).toBe(true);

    });

});
