const HTTP = require("../src/http.js");
const GENERIC = require("../src/generic.js");


describe("Check referrerPolicy()", () => {

    test("invalid headers", () => {

        expect(HTTP.referrerPolicy(undefined))
            .toEqual(GENERIC.INVALID_RESULT);

        expect(HTTP.referrerPolicy(""))
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

        expect(HTTP.referrerPolicy("same-origin"))
            .toEqual({
                result:true,
                data:{
                    value:"same-origin"
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

        expect(HTTP.featurePolicy("accelerometer 'none'; camera 'none'; geolocation 'none'; microphone 'none'; payment 'none'"))
            .toEqual({
                result:true,
                data:{
                    accelerometer:["'none'"],
                    camera:["'none'"],
                    geolocation:["'none'"],
                    microphone:["'none'"],
                    payment:["'none'"]
                }
            });

        expect(HTTP.featurePolicy("camera 'none'; geolocation 'src' https://example.com"))
            .toEqual({
                result:true,
                data:{
                    camera:["'none'"],
                    geolocation:[
                        "'src'",
                        "https://example.com"
                    ]
                }
            });

    });

    test("unsafe headers", () => {

        expect(HTTP.featurePolicy("camera https://example.com 'self'; microphone 'self' http://example.com"))
            .toEqual({
                result:false,
                data:{
                    camera:[
                        "https://example.com",
                        "'self'"
                    ],
                    microphone:[
                        "'self'",
                        "http://example.com"
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
