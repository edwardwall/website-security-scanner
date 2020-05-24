const HTTP = require("../src/http.js");
const GENERIC = require("../src/generic.js");


describe("Check xContentTypeOptions()", () => {

    test("invalid headers", () => {

        expect(HTTP.xContentTypeOptions(undefined))
            .toEqual(GENERIC.INVALID_RESULT);

        expect(HTTP.xContentTypeOptions(""))
            .toEqual(GENERIC.INVALID_RESULT);

        expect(HTTP.xContentTypeOptions("no sniff"))
            .toEqual(GENERIC.INVALID_RESULT);

    });

    test("valid headers", () => {

        expect(HTTP.xContentTypeOptions("nosniff"))
            .toEqual(GENERIC.VALID_RESULT);

    });

});


describe("Check xXssProtectionHeader()", () => {

    test("invalid headers", () => {

        const OUTPUT = {result:false};

        expect(HTTP.xXssProtectionHeader(undefined))
            .toEqual(OUTPUT);

        expect(HTTP.xXssProtectionHeader(""))
            .toEqual(OUTPUT);

        expect(HTTP.xXssProtectionHeader("0"))
            .toEqual(OUTPUT);

        expect(HTTP.xXssProtectionHeader("0;mode=block"))
            .toEqual(OUTPUT);

    });

    test("valid headers", () => {

        expect(HTTP.xXssProtectionHeader("1"))
            .toEqual({
                result:true,
                data:{
                    block:false
                }
            });

        expect(HTTP.xXssProtectionHeader("  1 ;mode=block"))
            .toEqual({
                result:true,
                data:{
                    block:true
                }
            });

        expect(HTTP.xXssProtectionHeader("  1 ; MODE = block"))
            .toEqual({
                result:true,
                data:{
                    block:true
                }
            });

    });

});
