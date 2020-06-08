const HTTP = require("../src/http.js");
const GENERIC = require("../src/generic.js");


describe("Check contentSecurityPolicy()", () => {

    test("insecure headers", () => {

        expect(HTTP.contentSecurityPolicy(
            "upgrade-insecure-requests"
        )).toEqual({
            result:false,
            data:{
                "upgrade-insecure-requests": []
            }
        });

        expect(HTTP.contentSecurityPolicy(
            "script-src 'none'; style-src https: 'self'"
        )).toEqual({
            result:false,
            data:{
                "script-src": ["'none'"],
                "style-src": ["https:", "'self'"]
            }
        });

    });

    test("secure headers", () => {

        expect(HTTP.contentSecurityPolicy(
            "default-src 'none'"
        )).toEqual({
            result:true,
            data:{
                "default-src": ["'none'"]
            }
        });

        expect(HTTP.contentSecurityPolicy(
            "script-src 'self'; style-src 'none'"
        )).toEqual({
            result:true,
            data:{
                "script-src": ["'self'"],
                "style-src": ["'none'"]
            }
        });

    });

});


describe("Check referrerPolicy()", () => {

    test("invalid headers", () => {

        expect(HTTP.referrerPolicy(undefined))
            .toEqual(GENERIC.INVALID_RESULT);

        expect(HTTP.referrerPolicy("no referrer"))
            .toEqual(GENERIC.INVALID_RESULT);

        expect(HTTP.referrerPolicy("unsafe-url"))
            .toEqual(GENERIC.INVALID_RESULT);

    });

    test("valid headers", () => {

        expect(HTTP.referrerPolicy("no-referrer"))
            .toEqual({
                result:true,
                data:{
                    value:"no-referrer"
                }
            });

        expect(HTTP.referrerPolicy("strict-origin-when-cross-origin"))
            .toEqual({
                result:true,
                data:{
                    value:"strict-origin-when-cross-origin"
                }
            });

    });

});


describe("Check featurePolicy()", () => {

    test("safe headers", () => {

        expect(HTTP.featurePolicy("camera 'none'; display-capture 'none'; geolocation 'none'; microphone 'none'; payment 'none'"))
            .toEqual({
                result:true,
                data:{
                    camera:["'none'"],
                    "display-capture":["'none'"],
                    geolocation:["'none'"],
                    microphone:["'none'"],
                    payment:["'none'"]
                }
            });

        expect(HTTP.featurePolicy("camera 'none'; display-capture 'none'; geolocation 'src' https://example.com; microphone 'none'; payment 'none'"))
            .toEqual({
                result:true,
                data:{
                    camera:["'none'"],
                    "display-capture":["'none'"],
                    geolocation:[
                        "'src'",
                        "https://example.com"
                    ],
                    microphone:["'none'"],
                    payment:["'none'"]
                }
            });

    });

    test("unsafe headers", () => {

        expect(HTTP.featurePolicy("camera https://example.com 'self'"))
            .toEqual({
                result:false,
                data:{
                    camera:[
                        "https://example.com",
                        "'self'"
                    ]
                }
            });

        expect(HTTP.featurePolicy("accelerometer 'none'; camera 'none'; geolocation *; microphone 'none';"))
            .toEqual({
                result:false,
                data:{
                    accelerometer:["'none'"],
                    camera:["'none'"],
                    geolocation:["*"],
                    microphone:["'none'"]
                }
            })

    });

    test("invalid headers", () => {

        expect(HTTP.featurePolicy(undefined)).toEqual({
            result:false,
            data:{}
        });

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


describe("Check miscellaneousHeaders()", () => {

    test("single headers", () => {

        expect(HTTP.miscellaneousHeaders([
            {server:"1"},
            {server:"123"},
            {server:"12"},
            {}
        ])).toEqual({
            asp:GENERIC.VALID_RESULT,
            powered:GENERIC.VALID_RESULT,
            server: {
                result: false,
                data: {
                    value: "123"
                }
            }
        });

        expect(HTTP.miscellaneousHeaders([
            {"x-powered-by":"123"},
            {"x-powered-by":"1"},
            {},
            {"x-powered-by":"12"}
        ])).toEqual({
            asp:GENERIC.VALID_RESULT,
            server:GENERIC.VALID_RESULT,
            powered: {
                result: false,
                data: {
                    value: "123"
                }
            }
        });

        expect(HTTP.miscellaneousHeaders([
            {},
            {"x-aspnet-version":"1", "x-aspnetmvc-version":"123"},
            {"x-aspnet-version":"12"},
            {"x-aspnetmvc-version":"12"}
        ])).toEqual({
            server:GENERIC.VALID_RESULT,
            powered:GENERIC.VALID_RESULT,
            asp: {
                result: false,
                data: {
                    value: "123"
                }
            }
        });

    });

});
