const HTTP = require("../src/http.js");
const GENERIC = require("../src/generic.js");


describe("Check referrerPolicy()", () => {

    test("invalid headers", () => {

        expect(HTTP.xFrameOptions(undefined))
            .toEqual(GENERIC.INVALID_RESULT);

        expect(HTTP.xFrameOptions(""))
            .toEqual(GENERIC.INVALID_RESULT);

        expect(HTTP.xFrameOptions("no referrer"))
            .toEqual(GENERIC.INVALID_RESULT);

        expect(HTTP.xFrameOptions("unsafe-url"))
            .toEqual(GENERIC.INVALID_RESULT);

    });

    test("valid headers", () => {

        expect(HTTP.xFrameOptions("no-referrer"))
            .toEqual(GENERIC.VALID_RESULT);

        expect(HTTP.xFrameOptions("same-origin"))
            .toEqual(GENERIC.VALID_RESULT);

        expect(HTTP.xFrameOptions("strict-origin-when-cross-origin"))
            .toEqual(GENERIC.VALID_RESULT);

    });

});


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


describe("Check xFrameOptions()", () => {

    test("invalid headers", () => {

        expect(HTTP.xFrameOptions(undefined))
            .toEqual(GENERIC.INVALID_RESULT);

        expect(HTTP.xFrameOptions(""))
            .toEqual(GENERIC.INVALID_RESULT);

    });

    test("valid headers", () => {

        expect(HTTP.xFrameOptions("deny"))
            .toEqual(GENERIC.VALID_RESULT);

        expect(HTTP.xFrameOptions("sameorigin"))
            .toEqual(GENERIC.VALID_RESULT);

        expect(HTTP.xFrameOptions("SAMEORIGIN"))
            .toEqual(GENERIC.VALID_RESULT);

    });

});


describe("Check xXssProtectionHeader()", () => {

    test("invalid headers", () => {

        expect(HTTP.xXssProtectionHeader(undefined))
            .toEqual(GENERIC.INVALID_RESULT);

        expect(HTTP.xXssProtectionHeader(""))
            .toEqual(GENERIC.INVALID_RESULT);

        expect(HTTP.xXssProtectionHeader("0"))
            .toEqual(GENERIC.INVALID_RESULT);

        expect(HTTP.xXssProtectionHeader("0;mode=block"))
            .toEqual(GENERIC.INVALID_RESULT);

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
