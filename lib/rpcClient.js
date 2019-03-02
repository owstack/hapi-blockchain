const request = require('request-promise-native');
const createError = require('errno').create;
const BlockchainError = createError('BlockchainError');
const RPCError = createError('RPCError', BlockchainError);

class RPCClient {
    constructor(config) {
        this.rpchost = config.rpchost;
        this.rpcport = config.rpcport;
        this.rpcuser = config.rpcuser;
        this.rpcprotocol = config.rpcprotocol;
        this.rpcpassword = config.rpcpassword;

        this.rpcUrl = `${this.rpcprotocol}://${this.rpchost}:${this.rpcport}`;
    }

    _getRandomId() {
        return parseInt(Math.random() * 100000);
    }

    async _rpcCall(rpcMethod, params = []) {
        try {
            const rpcCallResult = await request.post({
                url: this.rpcUrl,
                json: true,
                headers: {
                    Authorization: `Basic ${Buffer.from(`${this.rpcuser}:${this.rpcpassword}`).toString('base64')}`
                },
                body: {
                    jsonrpc: '1.0',
                    id: this._getRandomId(),
                    method: rpcMethod,
                    params: params
                }
            });
            return rpcCallResult.result || rpcCallResult;
        } catch (e) {
            const err = new RPCError(`${rpcMethod}, ${params}, ${e.message}`);
            err.code = e.code;
            throw err;
        }
    }

    async getBestBlockHash() {
        const method = 'getbestblockhash';
        return this._rpcCall(method);
    }

    async getBlock(hash, raw = true) {
        const method = 'getblock';
        return this._rpcCall(method, [hash, raw]);
    }

    async getBlockHash(height) {
        const method = 'getblockhash';
        return this._rpcCall(method, [height]);
    }

    async getBlockHeader(hash) {
        const method = 'getblockheader';
        return this._rpcCall(method, [hash]);
    }

    async getBlockchainInfo() {
        const method = 'getblockchaininfo';
        return this._rpcCall(method);
    }

    async getAddressBalance(addressObject) {
        const method = 'getaddressbalance';
        return this._rpcCall(method, [addressObject]);
    }

    async getAddressUtxos(addressObject) {
        const method = 'getaddressutxos';
        return this._rpcCall(method, [addressObject]);
    }

    async getAddressMempool(addressObject) {
        const method = 'getaddressmempool';
        return this._rpcCall(method, [addressObject]);
    }

    async getAddressTxids(addressObject) {
        const method = 'getaddresstxids';
        return this._rpcCall(method, [addressObject]);
    }

    async getBlockHashes(high, low, options) {
        const method = 'getblockhashes';
        return this._rpcCall(method, [high, low, options]);
    }

    async estimateFee(numBlocks) {
        const method = 'estimatefee';
        return this._rpcCall(method, [numBlocks]);
    }

    async estimateSmartFee(numBlocks) {
        const method = 'estimatesmartfee';
        return this._rpcCall(method, [numBlocks]);
    }

    async sendRawTransaction(rawTx) {
        const method = 'sendrawtransaction';
        return this._rpcCall(method, [rawTx]);
    }

    async getSpentInfo(options) {
        const method = 'getspentinfo';
        return this._rpcCall(method, [options]);
    }

    async getInfo() {
        const method = 'getinfo';
        return this._rpcCall(method);
    }

    async getNetworkInfo() {
        const method = 'getnetworkinfo';
        return this._rpcCall(method);
    }

    async getRawTransaction(txid, verbose) {
        const method = 'getrawtransaction';
        return this._rpcCall(method, [txid, verbose]);
    }

    async verifyMessage(bitcoinaddress, signature, message) {
        const method = 'verifymessage';
        return this._rpcCall(method, [bitcoinaddress, signature, message]);
    }
}

module.exports = RPCClient;
