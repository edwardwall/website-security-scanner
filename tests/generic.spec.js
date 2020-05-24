const GENERIC = require("../src/generic.js");


describe("Check checkHeaderKeyValue()", () => {

    const KEY = "key";
    const VALUE = "value";

    test("invalid kv pairs", () => {

        expect(GENERIC.checkHeaderKeyValue("1 key=value",
            KEY, VALUE)).toBe(false);

        expect(GENERIC.checkHeaderKeyValue("key=val ue",
            KEY, VALUE)).toBe(false);

        expect(GENERIC.checkHeaderKeyValue("key=notvalue",
            KEY, VALUE)).toBe(false);

        expect(GENERIC.checkHeaderKeyValue("key:value",
            KEY, VALUE)).toBe(false);

    });

    test("valid kv pairs", () => {

        expect(GENERIC.checkHeaderKeyValue("key=value",
            KEY, VALUE)).toBe(true);

        expect(GENERIC.checkHeaderKeyValue("1; key=value",
            KEY, VALUE)).toBe(true);

        expect(GENERIC.checkHeaderKeyValue("key = value",
            KEY, VALUE)).toBe(true);

        expect(GENERIC.checkHeaderKeyValue("KEY=value",
            KEY, VALUE)).toBe(true);

    });

});


describe("Check parsePolicy()", () => {

    test("malformed policies", () => {

        expect(() => {
            GENERIC.parsePolicy(undefined)
        }).toThrow();

    });

    test("valid policies", () => {

        expect(GENERIC.parsePolicy("example1 'unsafe' *; example2 http:"))
            .toEqual({
                example1:[
                    "'unsafe'",
                    "*"
                ],
                example2:[
                    "http:"
                ]
            });

    });

});
