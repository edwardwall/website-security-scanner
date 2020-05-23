const HTTPS = require("https")


async function get(url, callback) {

    HTTPS.get(url, (res) => {

        let body = "";

        res.on("data", (chunk) => {
            body += chunk.toString();
        });

        res.on("end", () => {
            callback(res.headers, body);
        });

    }).on("error", (err) => {
        callback(err);
    });

}


module.exports = {
    get
};
