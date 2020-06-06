const TLS = require("../src/tls.js");
const GENERIC = require("../src/generic.js");


describe("Check certificateValidity()", () => {

    test("valid certificates", () => {

        expect(TLS.certificateValidity({
            valid_from:"01 January 2020 01:00:00",
            valid_to:  "06 January 2020 01:00:00"
        })).toEqual({
            results:false,
            data:{
                length:5
            }
        });

        expect(TLS.certificateValidity({
            valid_from:"01 January 2020 01:00:00",
            valid_to:  "01 February 2020 01:00:00"
        })).toBe({
            results:false,
            data:{
                length:31
            }
        });

        expect(TLS.certificateValidity({
            valid_from:"01 January 2020 01:00:00",
            valid_to:  "01 July 2020 01:00:00"
        })).toBe({
            results:true,
            data:{
                length:(31+29+31+30+31+30)
            }
        });

        expect(TLS.certificateValidity({
            valid_from:"01 January 2020 01:00:00",
            valid_to:  "01 January 2021 01:00:00"
        })).toBe({
            results:true,
            data:{
                length:366 // Leap year
            }
        });

    });

});
