const pkg = require('./package.json');
const Blockchain = require('./lib/blockchain');

module.exports.plugin = {
    name: pkg.name,
    version: pkg.version,
    register: async function (server, config) {

        server.app.blockchain = new Blockchain(config);

        server.ext({
            type: 'onPreStart',
            method: async (srv) => {
                await srv.app.blockchain.start();
            }
        });

        server.ext({
            type: 'onPreStop',
            method: async (srv) => {
                await srv.app.blockchain.stop();
            }
        });
    }
};

module.exports.Blockchain = Blockchain;
