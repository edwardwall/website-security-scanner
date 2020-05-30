const TLS = require("tls");
const GENERIC = require("./generic.js");


/**
 * Check which TLS Protocols are enabled.
 * @param {string} host
 * @param {Object}
 */
async function checkProtocols(host) {

    return Promise.allSettled([
        checkProtocol("TLSv1.3"),
        checkProtocol("TLSv1.2"),
        checkProtocol("TLSv1.1"),
        checkProtocol("TLSv1")

    ]).then(([v3, v2, v1, v0]) => {

        return {
            "1.3": ("fulfilled" === v3.status),
            "1.2": ("fulfilled" === v2.status),
            "1.1": ("fulfilled" === v1.status),
            "1.0": ("fulfilled" === v0.status),
        };

    });


    /**
     * Private function to check specific protocol.
     * @param {string} protocol
     */
    async function checkProtocol(protocol) {
        return new Promise((resolve, reject) => {

            let options = {
                host,
                port:443,
                minVersion:protocol,
                maxVersion:protocol
            };

            try {
                let socket = TLS.connect(options, () => {
                    socket.destroy();
                    resolve();

                }).on("error", (err) => {
                    socket.destroy();
                    reject();
                }).on("timeout", (err) => {
                    socket.destroy();
                    reject();
                });
                socket.setTimeout(10000); // 10 seconds
            } catch (err) {
                reject();
            }

        });
    }

}


/**
 * Check whether server supports Forward Secrecy.
 * @param {Object} cipher
 * @returns {Result}
 */
function forwardSecrecy(cipher) {

    cipher = cipher.standardName;

    if (cipher.startsWith("TLS_")) { // Using TLS 1.3
        return GENERIC.VALID_RESULT;
    }

    for (e of ["dhe", "edh", "ecdhe"]) {

        if (cipher.includes(e)) {
            return GENERIC.VALID_RESULT;
        }
    }

    return GENERIC.INVALID_RESULT;

}


/**
 * @typedef {Result} ResultCertificate
 * @property {number} data.length
 */
/**
 * Check for Certificate validity.
 * @param {Object} certificate
 * @param {ResultCertificate}
 */
function certificateValidity(certificate) {

    if (undefined === certificate) {
        return GENERIC.INVALID_RESULT;
    }

    let start = Date.parse(certificate.valid_from);
    let end   = Date.parse(certificate.valid_to);

    let length = end - start;
    length /= 1000; // convert milliseconds to seconds
    length = GENERIC.secondsToDays(length);

    return {
        result: (190 >= length), // roughly 6 months
        data:{
            length
        }
    };

}


module.exports = {
    checkProtocols,
    forwardSecrecy,
    certificateValidity
};
