const TLS = require("../src/tls.js");
const GENERIC = require("../src/generic.js");


describe("Check forwardSecrecy()", () => {

    test("valid", () => {

        expect(TLS.forwardSecrecy({
            name: "TLS_AES_256_GCM_SHA384"
        })).toEqual(GENERIC.VALID_RESULT);

        expect(TLS.forwardSecrecy({
            name: "ECDHE-RSA-AES256-SHA"
        })).toEqual(GENERIC.VALID_RESULT);

    });

    test("invalid", () => {

        expect(TLS.forwardSecrecy({
            name: "RSA-AES256-SHA"
        })).toEqual(GENERIC.INVALID_RESULT);

    });

});


describe("Check certificateValidity()", () => {

    test("valid certificates", () => {

        expect(TLS.certificateValidity({
            valid_from:"01 January 2020 01:00:00",
            valid_to:  "11 January 2020 01:00:00"
        })).toEqual({
            result:true,
            data:{
                length:10
            }
        });

        expect(TLS.certificateValidity({
            valid_from:"01 January 2020 01:00:00",
            valid_to:  "01 January 2021 01:00:00"
        })).toEqual({
            result:false,
            data:{
                length:366 // Leap year
            }
        });

    });

    test("invalid values", () => {

        expect(TLS.certificateValidity(undefined))
            .toEqual(GENERIC.INVALID_RESULT);

    });

});
