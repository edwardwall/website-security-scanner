const MAIN = require("../src/main.js");

describe("Check parseLocation()", () => {

    test("parses correctly", () => {

        const OPTS = {
            protocol: "test:",
            hostname: "example.org",
            path: "/x/y/z"
        };

        expect(MAIN.parseLocation("https://example.com/a", OPTS))
            .toBe("https://example.com/a");

        expect(MAIN.parseLocation("//example.com/a", OPTS))
            .toBe("test://example.com/a");

        expect(MAIN.parseLocation("//example.com", OPTS))
            .toBe("test://example.com/");

        expect(MAIN.parseLocation("//a", OPTS))
            .toBe("test://example.org//a");

        expect(MAIN.parseLocation("//", OPTS))
            .toBe("test://example.org//");

        expect(MAIN.parseLocation("/a/b", OPTS))
            .toBe("test://example.org/a/b");

        expect(MAIN.parseLocation("a", OPTS))
            .toBe("test://example.org/x/y/a");

        expect(MAIN.parseLocation("a/b", OPTS))
            .toBe("test://example.org/x/y/a/b");

    });

});
