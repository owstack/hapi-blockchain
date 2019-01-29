const ltcLib = require('@owstack/ltc-lib');
const btcLib = require('@owstack/btc-lib');
const bchLib = require('@owstack/bch-lib');

const coinlib = {
    BCH: bchLib,
    BTC: btcLib,
    LTC: ltcLib
};

module.exports = coinlib;
