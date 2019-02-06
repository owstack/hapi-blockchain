const util = require('util');
const EventEmitter = require('events').EventEmitter;
const fs = require('fs');
const zmq = require('zeromq');
const LRU = require('lru-cache');
const retry = require('promise-retry');
const RPCClient = require('./rpcClient');

const coins = require('../lib/coins');

const owsCommon = require('@owstack/ows-common');
const _ = owsCommon.deps.lodash;
const $ = owsCommon.util.preconditions;
const Hash = owsCommon.Hash;

/**
 * Provides a friendly event driven API to bitcoind in Node.js. Manages connecting
 * to multiple bitcoind processes for server infrastructure. Results are cached in an
 * LRU cache for improved performance and methods added for common queries.
 *
 * @param {Object} options
 * @param {Node} options.currency - BTC, BCH, or LTC
 * @param {Node} options.nodes - An array of rpc connection objects
 */
function Blockchain(options = {currency: 'BTC', nodes: []}) {
    if (!(this instanceof Blockchain)) {
        return new Blockchain(options);
    }

    EventEmitter.call(this);
    this.options = options;

    this.coinLib = coins[options.currency];
    if (!this.coinLib) {
        throw new Error(`Currency ${options.currency} is not one of the available currencies: ${Object.keys(coins)}`);
    }

    this._initCaches();

    // set initial settings
    this._initDefaults(options);

    // available bitcoind nodes
    this._initClients();

    // for testing purposes
    this._process = options.process || process;

    this.node = {
        stopping: false
    };

    this.on('error', console.error);
}

util.inherits(Blockchain, EventEmitter);

Blockchain.DEFAULT_MAX_TXIDS = 1000;
Blockchain.DEFAULT_MAX_HISTORY = 50;
Blockchain.DEFAULT_SHUTDOWN_TIMEOUT = 15000;
Blockchain.DEFAULT_ZMQ_SUBSCRIBE_PROGRESS = 0.9999;
Blockchain.DEFAULT_MAX_ADDRESSES_QUERY = 10000;
Blockchain.DEFAULT_TRY_ALL_INTERVAL = 1000;
Blockchain.DEFAULT_REINDEX_INTERVAL = 10000;
Blockchain.DEFAULT_START_RETRY_INTERVAL = 5000;
Blockchain.DEFAULT_TIP_UPDATE_INTERVAL = 15000;
Blockchain.DEFAULT_TRANSACTION_CONCURRENCY = 5;

Blockchain.prototype._initDefaults = function (options) {
    /* jshint maxcomplexity: 15 */

    // limits
    this.maxTxids = options.maxTxids || Blockchain.DEFAULT_MAX_TXIDS;
    this.maxTransactionHistory = options.maxTransactionHistory || Blockchain.DEFAULT_MAX_HISTORY;
    this.maxAddressesQuery = options.maxAddressesQuery || Blockchain.DEFAULT_MAX_ADDRESSES_QUERY;
    this.shutdownTimeout = options.shutdownTimeout || Blockchain.DEFAULT_SHUTDOWN_TIMEOUT;

    // try all interval
    this.tryAllInterval = options.tryAllInterval || Blockchain.DEFAULT_TRY_ALL_INTERVAL;
    this.startRetryInterval = options.startRetryInterval || Blockchain.DEFAULT_START_RETRY_INTERVAL;

    // rpc limits
    this.transactionConcurrency = options.transactionConcurrency || Blockchain.DEFAULT_TRANSACTION_CONCURRENCY;

    // sync progress level when zmq subscribes to events
    this.zmqSubscribeProgress = options.zmqSubscribeProgress || Blockchain.DEFAULT_ZMQ_SUBSCRIBE_PROGRESS;
};

Blockchain.prototype._initCaches = function () {
    // caches valid until there is a new block
    this.utxosCache = LRU(50000);
    this.txidsCache = LRU(50000);
    this.balanceCache = LRU(50000);
    this.summaryCache = LRU(50000);
    this.blockOverviewCache = LRU(144);
    this.transactionDetailedCache = LRU(100000);

    // caches valid indefinitely
    this.transactionCache = LRU(100000);
    this.rawTransactionCache = LRU(50000);
    this.blockCache = LRU(144);
    this.rawBlockCache = LRU(72);
    this.blockHeaderCache = LRU(288);
    this.zmqKnownTransactions = LRU(5000);
    this.zmqKnownBlocks = LRU(50);
    this.lastTip = 0;
    this.lastTipTimeout = false;
};

Blockchain.prototype._initClients = function () {
    this.nodes = [];
    this.nodesIndex = 0;
    Object.defineProperty(this, 'client', {
        get: () => {
            const client = this.nodes[this.nodesIndex].client;
            this.nodesIndex = (this.nodesIndex + 1) % this.nodes.length;
            return client;
        },
        enumerable: true,
        configurable: false
    });
};

Blockchain.prototype._resetCaches = function () {
    this.transactionDetailedCache.reset();
    this.utxosCache.reset();
    this.txidsCache.reset();
    this.balanceCache.reset();
    this.summaryCache.reset();
    this.blockOverviewCache.reset();
};

Blockchain.prototype._tryAllClients = function (func) {
    const doit = (tryAgain) => {
        const client = this.client;
        return func(client)
            .catch(tryAgain);
    };

    return retry(doit, {retries: (this.nodes.length || 1) - 1, minTimeout: this.tryAllInterval || 1000, maxTimeout: this.tryAllInterval || 1000});
};

Blockchain.prototype._initChain = async function () {
    try {
        const bestBlockHash = await this.client.getBestBlockHash();
        const block = await this.client.getBlock(bestBlockHash);
        this.height = block.height;
        const genesisBlockHash = await this.client.getBlockHash(0);
        this.genesisBuffer = await this.getRawBlock(genesisBlockHash);
        this.emit('ready');
        console.log('Blockchain Daemon Ready');
    } catch (e) {
        throw e;
    }
};

Blockchain.prototype._zmqBlockHandler = function (node, message) {
    // Update the current chain tip
    this._rapidProtectedUpdateTip(node, message);

    // Notify block subscribers
    const id = message.toString('binary');
    if (!this.zmqKnownBlocks.get(id)) {
        this.zmqKnownBlocks.set(id, true);
        this.emit('block', message);
    }
};

Blockchain.prototype._rapidProtectedUpdateTip = function (node, message) {
    // Prevent a rapid succession of tip updates
    if (new Date() - this.lastTip > 1000) {
        this.lastTip = new Date();
        this._updateTip(node, message);
    } else {
        clearTimeout(this.lastTipTimeout);
        this.lastTipTimeout = setTimeout(() => {
            this._updateTip(node, message);
        }, 1000);
    }
};

Blockchain.prototype._updateTip = function (node, message) {
    const hex = message.toString('hex');
    if (hex !== this.tiphash) {
        this.tiphash = hex;

        // reset block valid caches
        this._resetCaches();
        const updateTip = async () => {
            try {
                const block = await node.client.getBlock(this.tiphash);

                this.height = block.height;
                $.checkState(this.height >= 0);

                if (!this.node.stopping) {

                    const percentage = await this.syncPercentage();

                    if (Math.round(percentage) >= 100) {
                        this.emit('synced', this.height);
                    } else {
                        console.log('Blockchain Height:', this.height, 'Percentage:', percentage.toFixed(2));
                    }
                }

                this.emit('tip', this.height);
            } catch (e) {
                this.emit('error', e);
            }
        };
        updateTip();
    }
};

Blockchain.prototype._getAddressesFromTransaction = function (transaction) {
    const addresses = [];

    for (let i = 0; i < transaction.inputs.length; i++) {
        const input = transaction.inputs[i];
        if (input.script) {
            const inputAddress = input.script.toAddress(this.node.network);
            if (inputAddress) {
                addresses.push(inputAddress.toString());
            }
        }
    }

    for (let j = 0; j < transaction.outputs.length; j++) {
        const output = transaction.outputs[j];
        if (output.script) {
            const outputAddress = output.script.toAddress(this.node.network);
            if (outputAddress) {
                addresses.push(outputAddress.toString());
            }
        }
    }

    return _.uniq(addresses);
};

Blockchain.prototype._notifyAddressTxidSubscribers = function (txid, transaction) {
    const addresses = this._getAddressesFromTransaction(transaction);
    for (let i = 0; i < addresses.length; i++) {
        const address = addresses[i];
        this.emit('address', {
            address: address,
            txid: txid
        });
    }
};

Blockchain.prototype._zmqTransactionHandler = function (node, message) {
    const hash = Hash.sha256sha256(message);
    const id = hash.toString('binary');
    if (!this.zmqKnownTransactions.get(id)) {
        this.zmqKnownTransactions.set(id, true);
        this.emit('tx', message);

        const tx = this.coinLib.Transaction();
        tx.fromString(message);
        const txid = tx.id;
        this._notifyAddressTxidSubscribers(txid, tx);
    }
};

Blockchain.prototype._checkSyncedAndSubscribeZmqEvents = async function (node) {
    let interval;

    const checkAndSubscribe = async () => {
        try {
            const bestBlockHash = await node.client.getBestBlockHash();
            const blockhash = Buffer.from(bestBlockHash, 'hex');
            this.emit('block', blockhash);
            this._updateTip(node, blockhash);

            const blockchainInfo = await node.client.getBlockchainInfo();
            const progress = blockchainInfo.verificationprogress;

            if (progress >= this.zmqSubscribeProgress) {
                this._subscribeZmqEvents(node);
                clearInterval(interval);
                return true;
            } else {
                return false;
            }
        } catch (e) {
            throw e;
        }
    };

    let synced;
    try {
        synced = await checkAndSubscribe();
    } catch (e) {
        console.error(e);
    }

    if (!synced) {
        interval = setInterval(async () => {
            if (this.node.stopping) {
                return clearInterval(interval);
            }
            try {
                await checkAndSubscribe();
            } catch (e) {
                console.error(e);
            }
        }, node._tipUpdateInterval || Blockchain.DEFAULT_TIP_UPDATE_INTERVAL);
    }
};

Blockchain.prototype._subscribeZmqEvents = function (node) {
    node.zmqSubSocket.subscribe('hashblock');
    node.zmqSubSocket.subscribe('rawtx');
    node.zmqSubSocket.on('message', (topic, message) => {
        const topicString = topic.toString('utf8');
        if (topicString === 'rawtx') {
            this._zmqTransactionHandler(node, message);
        } else if (topicString === 'hashblock') {
            this._zmqBlockHandler(node, message);
        }
    });
};

Blockchain.prototype._initZmqSubSocket = function (node, zmqUrl) {
    node.zmqSubSocket = zmq.socket('sub');

    node.zmqSubSocket.on('connect', function (fd, endPoint) {
        console.log('ZMQ connected to:', endPoint);
    });

    node.zmqSubSocket.on('connect_delay', function (fd, endPoint) {
        console.warn('ZMQ connection delay:', endPoint);
    });

    node.zmqSubSocket.on('disconnect', function (fd, endPoint) {
        console.warn('ZMQ disconnect:', endPoint);
    });

    node.zmqSubSocket.on('monitor_error', function (err) {
        console.error('Error in monitoring: %s, will restart monitoring in 5 seconds', err);
        setTimeout(function () {
            node.zmqSubSocket.monitor(500, 0);
        }, 5000);
    });

    node.zmqSubSocket.monitor(500, 0);
    node.zmqSubSocket.connect(zmqUrl);
};

Blockchain.prototype._loadTipFromNode = async function (node) {
    try {
        const bestBlockHash = await node.client.getBestBlockHash();
        const block = await node.client.getBlock(bestBlockHash);
        this.height = block.height;
        $.checkState(this.height >= 0);
        this.emit('tip', this.height);
    } catch (e) {
        if (e.code === -28) {
            console.warn(e.message);
        }
        throw e;
    }
};

Blockchain.prototype._connectProcess = async function (config) {
    let exitShutdown = false;

    const connectProcess = async (tryAgain) => {
        const node = {};

        if (this.node.stopping) {
            exitShutdown = true;
            return;
        }

        node.client = new RPCClient({
            protocol: config.rpcprotocol || 'http',
            host: config.rpchost || '127.0.0.1',
            port: config.rpcport,
            user: config.rpcuser,
            pass: config.rpcpassword
        });

        try {
            await this._loadTipFromNode(node);
        } catch (e) {
            tryAgain(e);
        }
        return node;
    };

    const node = await retry(connectProcess, {retries: 59, minTimeout: this.startRetryInterval, maxTimeout: this.startRetryInterval});

    if (exitShutdown) {
        throw new Error('Stopping while trying to connect to bitcoind.');
    }

    if (config.zmqpubhashblock && config.zmqpubrawtx && config.zmqpubhashblock !== config.zmqpubrawtx) {
        throw new Error('config.zmqpubrawtx and config.zmqpubhashblock should match');
    }

    this._initZmqSubSocket(node, config.zmqpubrawtx);
    this._subscribeZmqEvents(node);

    return node;
};

Blockchain.prototype.start = async function () {

    const promises = [];
    for (const node in this.options.nodes) {
        promises.push(this._connectProcess(node));
    }

    try {
        this.nodes = await Promise.all(promises);
    } catch (e) {
        throw e;
    }

    if (this.nodes.length === 0) {
        throw new Error('Blockchain configuration options "nodes" are expected');
    }

    return this._initChain();
};

Blockchain.prototype.isSynced = async function () {
    try {
        const percentage = await this.syncPercentage();
        if (Math.round(percentage) >= 100) {
            return true;
        }
        return false;
    } catch (e) {
        throw e;
    }
};

Blockchain.prototype.syncPercentage = async function () {
    try {
        const blockchainInfo = await this.client.getBlockchainInfo();
        return blockchainInfo.verificationprogress * 100;
    } catch (e) {
        throw e;
    }
};

Blockchain.prototype._normalizeAddressArg = function (addressArg) {
    let addresses = [addressArg];
    if (Array.isArray(addressArg)) {
        addresses = addressArg;
    }
    return addresses;
};

/**
 * Will get the balance for an address or multiple addresses
 * @param {String|Address|Array} addressArg - An address string, btc address, or array of addresses
 */
Blockchain.prototype.getAddressBalance = async function (addressArg) {
    const addresses = this._normalizeAddressArg(addressArg);
    const cacheKey = addresses.join('');
    let balance = this.balanceCache.get(cacheKey);
    if (balance) {
        return balance;
    } else {
        try {
            balance = await this.client.getAddressBalance({addresses});
        } catch (e) {
            throw e;
        }
        this.balanceCache.set(cacheKey, balance);
        return balance;
    }
};

/**
 * Will get the unspent outputs for an address or multiple addresses
 * @param {String|Address|Array} addressArg - An address string, btc address, or array of addresses
 * @param {Object} options
 */
Blockchain.prototype.getAddressUnspentOutputs = async function (addressArg, options) {
    const queryMempool = _.isUndefined(options.queryMempool) ? true : options.queryMempool;
    const addresses = this._normalizeAddressArg(addressArg);
    const cacheKey = addresses.join('');
    let utxos = this.utxosCache.get(cacheKey);

    const transformUnspentOutput = (delta) => {
        const script = this.coinLib.Script.fromAddress(delta.address);
        return {
            address: delta.address,
            txid: delta.txid,
            outputIndex: delta.index,
            script: script.toHex(),
            satoshis: delta.satoshis,
            timestamp: delta.timestamp
        };
    };

    const updateWithMempool = (confirmedUtxos, mempoolDeltas) => {
        if (!mempoolDeltas || !mempoolDeltas.length) {
            return confirmedUtxos;
        }
        let isSpentOutputs = false;
        const mempoolUnspentOutputs = [];
        const spentOutputs = [];

        for (let i = 0; i < mempoolDeltas.length; i++) {
            const delta = mempoolDeltas[i];
            if (delta.prevtxid && delta.satoshis <= 0) {
                if (!spentOutputs[delta.prevtxid]) {
                    spentOutputs[delta.prevtxid] = [delta.prevout];
                } else {
                    spentOutputs[delta.prevtxid].push(delta.prevout);
                }
                isSpentOutputs = true;
            } else {
                mempoolUnspentOutputs.push(transformUnspentOutput(delta));
            }
        }

        const utxos = mempoolUnspentOutputs.reverse().concat(confirmedUtxos);

        if (isSpentOutputs) {
            return utxos.filter(function (utxo) {
                if (!spentOutputs[utxo.txid]) {
                    return true;
                } else {
                    return (spentOutputs[utxo.txid].indexOf(utxo.outputIndex) === -1);
                }
            });
        }

        return utxos;
    };

    let addressMempool = [];
    try {
        if (queryMempool) {
            addressMempool = await this.client.getAddressMempool({addresses});
        }
        if (!utxos) {
            utxos = await this.client.getAddressUtxos({addresses});
            utxos = utxos.reverse();
            this.utxosCache.set(cacheKey, utxos);
        }
    } catch (e) {
        throw e;
    }

    return updateWithMempool(utxos, addressMempool);
};

Blockchain.prototype._getBalanceFromMempool = function (deltas) {
    let satoshis = 0;
    for (let i = 0; i < deltas.length; i++) {
        satoshis += deltas[i].satoshis;
    }
    return satoshis;
};

Blockchain.prototype._getTxidsFromMempool = function (deltas) {
    const mempoolTxids = [];
    const mempoolTxidsKnown = {};
    for (let i = 0; i < deltas.length; i++) {
        const txid = deltas[i].txid;
        if (!mempoolTxidsKnown[txid]) {
            mempoolTxids.push(txid);
            mempoolTxidsKnown[txid] = true;
        }
    }
    return mempoolTxids;
};

Blockchain.prototype._getHeightRangeQuery = function (options, clone) {
    if (options.start >= 0 && options.end >= 0) {
        if (options.end > options.start) {
            throw new TypeError('"end" is expected to be less than or equal to "start"');
        }
        if (clone) {
            // reverse start and end as the order in btc is most recent to less recent
            clone.start = options.end;
            clone.end = options.start;
        }
        return true;
    }
    return false;
};

/**
 * Will get the txids for an address or multiple addresses
 * @param {String|Address|Array} addressArg - An address string, btc address, or array of addresses
 * @param {Object} options
 */
Blockchain.prototype.getAddressTxids = async function (addressArg, options) {
    let queryMempool = _.isUndefined(options.queryMempool) ? true : options.queryMempool;
    const queryMempoolOnly = _.isUndefined(options.queryMempoolOnly) ? false : options.queryMempoolOnly;
    let rangeQuery = false;
    try {
        rangeQuery = this._getHeightRangeQuery(options);
    } catch (e) {
        throw e;
    }
    if (rangeQuery) {
        queryMempool = false;
    }
    if (queryMempoolOnly) {
        queryMempool = true;
        rangeQuery = false;
    }
    const addresses = this._normalizeAddressArg(addressArg);
    const cacheKey = addresses.join('');
    let mempoolTxids = [];
    const txids = queryMempoolOnly ? false : this.txidsCache.get(cacheKey);

    try {
        if (queryMempool) {
            const addressMempool = await this.client.getAddressMempool({addresses: addresses});
            mempoolTxids = this._getTxidsFromMempool(addressMempool);
        }

        if (queryMempoolOnly) {
            return mempoolTxids.reverse();
        }
        if (txids && !rangeQuery) {
            const allTxids = mempoolTxids.reverse().concat(txids);
            return allTxids;
        } else {
            const txidOpts = {
                addresses: addresses
            };
            if (rangeQuery) {
                this._getHeightRangeQuery(options, txidOpts);
            }
            const addressTxids = await this.client.getAddressTxids(txidOpts);
            addressTxids.reverse();

            if (!rangeQuery) {
                this.txidsCache.set(cacheKey, addressTxids);
            }

            return mempoolTxids.reverse().concat(addressTxids);
        }
    } catch (e) {
        throw e;
    }
};

Blockchain.prototype._getConfirmationsDetail = function (transaction) {
    $.checkState(this.height > 0, 'current height is unknown');
    let confirmations = 0;
    if (transaction.height >= 0) {
        confirmations = this.height - transaction.height + 1;
    }
    if (confirmations < 0) {
        console.warn('Negative confirmations calculated for transaction:', transaction.hash);
    }
    return Math.max(0, confirmations);
};

Blockchain.prototype._getAddressDetailsForInput = function (input, inputIndex, result, addressStrings) {
    if (!input.address) {
        return;
    }
    const address = input.address;
    if (addressStrings.indexOf(address) >= 0) {
        if (!result.addresses[address]) {
            result.addresses[address] = {
                inputIndexes: [inputIndex],
                outputIndexes: []
            };
        } else {
            result.addresses[address].inputIndexes.push(inputIndex);
        }
        result.satoshis -= input.satoshis;
    }
};

Blockchain.prototype._getAddressDetailsForOutput = function (output, outputIndex, result, addressStrings) {
    if (!output.address) {
        return;
    }
    const address = output.address;
    if (addressStrings.indexOf(address) >= 0) {
        if (!result.addresses[address]) {
            result.addresses[address] = {
                inputIndexes: [],
                outputIndexes: [outputIndex]
            };
        } else {
            result.addresses[address].outputIndexes.push(outputIndex);
        }
        result.satoshis += output.satoshis;
    }
};

Blockchain.prototype._getAddressDetailsForTransaction = function (transaction, addressStrings) {
    const result = {
        addresses: {},
        satoshis: 0
    };

    for (let inputIndex = 0; inputIndex < transaction.inputs.length; inputIndex++) {
        const input = transaction.inputs[inputIndex];
        this._getAddressDetailsForInput(input, inputIndex, result, addressStrings);
    }

    for (let outputIndex = 0; outputIndex < transaction.outputs.length; outputIndex++) {
        const output = transaction.outputs[outputIndex];
        this._getAddressDetailsForOutput(output, outputIndex, result, addressStrings);
    }

    $.checkState(Number.isFinite(result.satoshis));

    return result;
};

/**
 * Will expand into a detailed transaction from a txid
 * @param {Object} txid - A bitcoin transaction id
 */
Blockchain.prototype._getAddressDetailedTransaction = async function (txid, options) {
    let transaction;
    try {
        transaction = await this.getDetailedTransaction(txid);
    } catch (e) {
        throw e;
    }

    const addressDetails = this._getAddressDetailsForTransaction(transaction, options.addressStrings);

    const details = {
        addresses: addressDetails.addresses,
        satoshis: addressDetails.satoshis,
        confirmations: this._getConfirmationsDetail(transaction),
        tx: transaction
    };

    return details;
};

Blockchain.prototype._getAddressStrings = function (addresses) {
    const addressStrings = [];
    for (let i = 0; i < addresses.length; i++) {
        const address = addresses[i];
        if (address instanceof this.coinLib.Address) {
            addressStrings.push(address.toString());
        } else if (_.isString(address)) {
            addressStrings.push(address);
        } else {
            throw new TypeError('Addresses are expected to be strings');
        }
    }
    return addressStrings;
};

Blockchain.prototype._paginateTxids = function (fullTxids, fromArg, toArg) {
    const from = parseInt(fromArg);
    const to = parseInt(toArg);
    $.checkState(from < to, `"from" (${  from  }) is expected to be less than "to" (${  to  })`);
    return fullTxids.slice(from, to);
};

/**
 * Will detailed transaction history for an address or multiple addresses
 * @param {String|Address|Array} addressArg - An address string, btc address, or array of addresses
 * @param {Object} options
 */
Blockchain.prototype.getAddressHistory = async function (addressArg, options = {}) {
    const addresses = this._normalizeAddressArg(addressArg);
    if (addresses.length > this.maxAddressesQuery) {
        throw new TypeError(`Maximum number of addresses (${this.maxAddressesQuery}) exceeded`);
    }

    const queryMempool = _.isUndefined(options.queryMempool) ? true : options.queryMempool;
    const addressStrings = this._getAddressStrings(addresses);

    const fromArg = parseInt(options.from || 0);
    const toArg = parseInt(options.to || this.maxTransactionHistory);

    if ((toArg - fromArg) > this.maxTransactionHistory) {
        throw new Error(`"from" (${options.from}) and "to" (${options.to}) range should be less than or equal to ${this.maxTransactionHistory}`);
    }

    try {
        let txids = await this.getAddressTxids(addresses, options);
        const totalCount = txids.length;
        txids = this._paginateTxids(txids, fromArg, toArg);
        const transactions = await Promise.all(txids.map((txid) => {
            return this._getAddressDetailedTransaction(txid,  {
                queryMempool: queryMempool,
                addressStrings: addressStrings
            });
        }));

        return {
            totalCount: totalCount,
            items: transactions
        };
    } catch (e) {
        throw e;
    }
};

/**
 * Will get the summary including txids and balance for an address or multiple addresses
 * @param {String|Address|Array} addressArg - An address string, btc address, or array of addresses
 * @param {Object} options
 */
Blockchain.prototype.getAddressSummary = async function (addressArg, options = {}) {
    const summary = {};
    const queryMempool = _.isUndefined(options.queryMempool) ? true : options.queryMempool;
    let summaryTxids = [];
    let mempoolTxids = [];
    const addresses = this._normalizeAddressArg(addressArg);
    const cacheKey = addresses.join('');

    if (options.noTxList) {
        const summaryCache = this.summaryCache.get(cacheKey);
        if (summaryCache) {
            return summaryCache;
        }
    }

    try {
        const txids = await this.getAddressTxids(addresses, {queryMempool: false});
        summaryTxids = txids;
        summary.appearances = txids.length;

        const addressBalance = await this.getAddressBalance(addresses, options);
        summary.totalReceived = addressBalance.received;
        summary.totalSpent = addressBalance.received - addressBalance.balance;
        summary.balance = addressBalance.balance;

        if (queryMempool) {
            const addressMempool = await this.client.getAddressMempool({addresses: addresses});
            mempoolTxids = this._getTxidsFromMempool(addressMempool);
            summary.unconfirmedAppearances = mempoolTxids.length;
            summary.unconfirmedBalance = this._getBalanceFromMempool(addressMempool);
        }
        this.summaryCache.set(cacheKey, summary);
    } catch (e) {
        throw e;
    }

    if (!options.noTxList) {
        const allTxids = mempoolTxids.reverse().concat(summaryTxids);
        const fromArg = parseInt(options.from || 0);
        const toArg = parseInt(options.to || this.maxTxids);

        if ((toArg - fromArg) > this.maxTxids) {
            throw new Error(`"from" (${fromArg}) and "to" (${toArg}) range should be less than or equal to ${this.maxTxids}`);
        }
        let paginatedTxids;
        try {
            paginatedTxids = this._paginateTxids(allTxids, fromArg, toArg);
        } catch (e) {
            throw e;
        }

        const allSummary = _.clone(summary);
        allSummary.txids = paginatedTxids;
        return allSummary;
    } else {
        return summary;
    }
};

Blockchain.prototype._maybeGetBlockHash = async function (blockArg) {
    if (_.isNumber(blockArg) || (blockArg.length < 40 && /^[0-9]+$/.test(blockArg))) {
        const blockHash = await this._tryAllClients(async (client) => {
            try {
                const blockHash = await client.getBlockHash(blockArg);
                return blockHash;
            } catch (e) {
                throw e;
            }
        });
        return blockHash;
    } else {
        return blockArg;
    }
};

/**
 * Will retrieve a block as a Node.js Buffer
 * @param {String|Number} block - A block hash or block height number
 */
Blockchain.prototype.getRawBlock = async function (blockArg) {
    // TODO apply performance patch to the RPC method for raw data
    const cachedBlock = this.rawBlockCache.get(blockArg);
    if (cachedBlock) {
        return cachedBlock;
    } else {
        try {
            const blockhash = await this._maybeGetBlockHash(blockArg);
            const buffer = await this._tryAllClients(async (client) => {
                try {
                    const block = await client.getBlock(blockhash, false);
                    const buffer = Buffer.from(block, 'hex');
                    this.rawBlockCache.set(blockhash, buffer);
                    return buffer;
                } catch (e) {
                    throw e;
                }
            });
            return buffer;
        } catch (e) {
            throw e;
        }
    }
};

/**
 * Similar to getBlockHeader but will include a list of txids
 * @param {String|Number} block - A block hash or block height number
 */
Blockchain.prototype.getBlockOverview = async function (blockArg) {
    try {
        const blockhash = await this._maybeGetBlockHash(blockArg);
        const cachedBlock = this.blockOverviewCache.get(blockhash);
        if (cachedBlock) {
            return cachedBlock;
        } else {
            const blockOverview = await this._tryAllClients(async (client) => {
                try {
                    const block = await client.getBlock(blockhash);
                    const blockOverview = {
                        hash: block.hash,
                        version: block.version,
                        confirmations: block.confirmations,
                        height: block.height,
                        chainWork: block.chainwork,
                        prevHash: block.previousblockhash,
                        nextHash: block.nextblockhash,
                        merkleRoot: block.merkleroot,
                        time: block.time,
                        medianTime: block.mediantime,
                        nonce: block.nonce,
                        bits: block.bits,
                        difficulty: block.difficulty,
                        txids: block.tx
                    };
                    this.blockOverviewCache.set(blockhash, blockOverview);
                    return blockOverview;
                } catch (e) {
                    throw e;
                }
            });
            return blockOverview;
        }
    } catch (e) {
        throw e;
    }
};

/**
 * Will retrieve a block
 * @param {String|Number} block - A block hash or block height number
 */
Blockchain.prototype.getBlock = async function (blockArg) {
    // TODO apply performance patch to the RPC method for raw data
    try {
        const blockhash = await this._maybeGetBlockHash(blockArg);
        const cachedBlock = this.blockCache.get(blockhash);
        if (cachedBlock) {
            return cachedBlock;
        } else {
            const blockObj = await this._tryAllClients(async (client) => {
                try {
                    const block = await client.getBlock(blockhash, false);
                    const blockObj = this.coinLib.Block.fromString(block);
                    this.blockCache.set(blockhash, blockObj);
                    return blockObj;
                } catch (e) {
                    throw e;
                }
            });
            return blockObj;
        }
    } catch (e) {
        throw e;
    }
};

/**
 * Will retrieve an array of block hashes within a range of timestamps
 * @param {Number} high - The more recent timestamp in seconds
 * @param {Number} low - The older timestamp in seconds
 */
Blockchain.prototype.getBlockHashesByTimestamp = async function (high, low, options = {}) {
    try {
        const hashes = await this.client.getBlockHashes(high, low, options);
        return hashes;
    } catch (e) {
        throw e;
    }
};

/**
 * Will return the block index information, the output will have the format:
 * {
 *   hash: '0000000000000a817cd3a74aec2f2246b59eb2cbb1ad730213e6c4a1d68ec2f6',
 *   confirmations: 5,
 *   height: 828781,
 *   chainWork: '00000000000000000000000000000000000000000000000ad467352c93bc6a3b',
 *   prevHash: '0000000000000504235b2aff578a48470dbf6b94dafa9b3703bbf0ed554c9dd9',
 *   nextHash: '00000000000000eedd967ec155f237f033686f0924d574b946caf1b0e89551b8'
 *   version: 536870912,
 *   merkleRoot: '124e0f3fb5aa268f102b0447002dd9700988fc570efcb3e0b5b396ac7db437a9',
 *   time: 1462979126,
 *   medianTime: 1462976771,
 *   nonce: 2981820714,
 *   bits: '1a13ca10',
 *   difficulty: 847779.0710240941,
 * }
 * @param {String|Number} block - A block hash or block height
 */
Blockchain.prototype.getBlockHeader = async function (blockArg) {
    try {
        const blockhash = await this._maybeGetBlockHash(blockArg);
        const header = await this._tryAllClients(async (client) => {
            try {
                const blockHeader = await client.getBlockHeader(blockhash);
                const header = {
                    hash: blockHeader.hash,
                    version: blockHeader.version,
                    confirmations: blockHeader.confirmations,
                    height: blockHeader.height,
                    chainWork: blockHeader.chainwork,
                    prevHash: blockHeader.previousblockhash,
                    nextHash: blockHeader.nextblockhash,
                    merkleRoot: blockHeader.merkleroot,
                    time: blockHeader.time,
                    medianTime: blockHeader.mediantime,
                    nonce: blockHeader.nonce,
                    bits: blockHeader.bits,
                    difficulty: blockHeader.difficulty
                };
                return header;
            } catch (e) {
                throw e;
            }
        });
        return header;
    } catch (e) {
        throw e;
    }
};

/**
 * Will estimate the fee per kilobyte.
 * @param {Number} blocks - The number of blocks for the transaction to be confirmed.
 */
Blockchain.prototype.estimateFee = async function (blocks) {
    try {
        const feePerKb = await this.client.estimateFee(blocks);
        return feePerKb;
    } catch (e) {
        throw e;
    }
};

/**
 * Will estimate the fee per kilobyte.
 * @param {Number} blocks - The number of blocks for the transaction to be confirmed.
 */
Blockchain.prototype.estimateSmartFee = async function (blocks) {
    try {
        const feePerKb = await this.client.estimateSmartFee(blocks);
        return feePerKb;
    } catch (e) {
        throw e;
    }
};

/**
 * Will estimate the fee per kilobyte.
 * @param {Number} blocks - The number of blocks for the transaction to be confirmed.
 */
Blockchain.prototype.verifyMessage = async function (address, signature, message) {
    try {
        const response = await this.client.verifyMessage(address, signature, message);
        return response;
    } catch (e) {
        throw e;
    }
};

/**
 * Will add a transaction to the mempool and relay to connected peers
 * @param {String|Transaction} transaction - The hex string of the transaction
 * @param {Object=} options
 * @param {Boolean=} options.allowAbsurdFees - Enable large fees
 */
Blockchain.prototype.sendTransaction = async function (tx, options = {}) {
    try {
        const allowAbsurdFees = options.allowAbsurdFees;
        const sendTxResult = await this.client.sendRawTransaction(tx, allowAbsurdFees);
        if (typeof this.options.sendTxLog === 'string') {
            fs.appendFile(this.options.sendTxLog, `${tx}\n`, function (err) {
                if (err) {
                    // error on logging tx -> write to error log, but still return success to user
                    console.error(err);
                }
            });
        }
        return sendTxResult;
    } catch (e) {
        throw e;
    }
};

/**
 * Will get a transaction as a Node.js Buffer. Results include the mempool.
 * @param {String} txid - The transaction hash
 */
Blockchain.prototype.getRawTransaction = async function (txid) {
    const tx = this.rawTransactionCache.get(txid);
    if (tx) {
        return tx;
    } else {
        const rawTx = await this._tryAllClients(async (client) => {
            try {
                const rawTx = await client.getRawTransaction(txid);
                const buffer = Buffer.from(rawTx, 'hex');
                this.rawTransactionCache.set(txid, buffer);
                return buffer;
            } catch (e) {
                throw e;
            }
        });
        return rawTx;
    }
};

/**
 * Will get a Transaction. Results include the mempool.
 * @param {String} txid - The transaction hash
 * @param {Boolean} queryMempool - Include the mempool
 */
Blockchain.prototype.getTransaction = async function (txid) {
    const Transaction = this.coinLib.Transaction;
    const tx = this.transactionCache.get(txid);
    if (tx) {
        return tx;
    } else {
        const tx = await this._tryAllClients(async (client) => {
            try {
                const rawTx = await client.getRawTransaction(txid);
                const tx = Transaction();
                tx.fromString(rawTx);
                this.transactionCache.set(txid, tx);
                return tx;
            } catch (e) {
                throw e;
            }
        });
        return tx;
    }
};

/**
 * Will get a detailed view of a transaction including addresses, amounts and fees.
 *
 * Example result:
 * {
 *   blockHash: '000000000000000002cd0ba6e8fae058747d2344929ed857a18d3484156c9250',
 *   height: 411462,
 *   blockTimestamp: 1463070382,
 *   version: 1,
 *   hash: 'de184cc227f6d1dc0316c7484aa68b58186a18f89d853bb2428b02040c394479',
 *   locktime: 411451,
 *   coinbase: true,
 *   inputs: [
 *     {
 *       prevTxId: '3d003413c13eec3fa8ea1fe8bbff6f40718c66facffe2544d7516c9e2900cac2',
 *       outputIndex: 0,
 *       sequence: 123456789,
 *       script: [hexString],
 *       scriptAsm: [asmString],
 *       address: '1LCTmj15p7sSXv3jmrPfA6KGs6iuepBiiG',
 *       satoshis: 771146
 *     }
 *   ],
 *   outputs: [
 *     {
 *       satoshis: 811146,
 *       script: '76a914d2955017f4e3d6510c57b427cf45ae29c372c99088ac',
 *       scriptAsm: 'OP_DUP OP_HASH160 d2955017f4e3d6510c57b427cf45ae29c372c990 OP_EQUALVERIFY OP_CHECKSIG',
 *       address: '1LCTmj15p7sSXv3jmrPfA6KGs6iuepBiiG',
 *       spentTxId: '4316b98e7504073acd19308b4b8c9f4eeb5e811455c54c0ebfe276c0b1eb6315',
 *       spentIndex: 1,
 *       spentHeight: 100
 *     }
 *   ],
 *   inputSatoshis: 771146,
 *   outputSatoshis: 811146,
 *   feeSatoshis: 40000
 * };
 *
 * @param {String} txid - The hex string of the transaction
 */
Blockchain.prototype.getDetailedTransaction = async function (txid) {
    const tx = this.transactionDetailedCache.get(txid);

    function addInputsToTx(tx, result) {
        tx.inputs = [];
        tx.inputSatoshis = 0;
        for (let inputIndex = 0; inputIndex < result.vin.length; inputIndex++) {
            const input = result.vin[inputIndex];
            if (!tx.coinbase) {
                tx.inputSatoshis += input.valueSat;
            }
            let script = null;
            let scriptAsm = null;
            if (input.scriptSig) {
                script = input.scriptSig.hex;
                scriptAsm = input.scriptSig.asm;
            } else if (input.coinbase) {
                script = input.coinbase;
            }
            tx.inputs.push({
                prevTxId: input.txid || null,
                outputIndex: _.isUndefined(input.vout) ? null : input.vout,
                script: script,
                scriptAsm: scriptAsm || null,
                sequence: input.sequence,
                address: input.address || null,
                satoshis: _.isUndefined(input.valueSat) ? null : input.valueSat
            });
        }
    }

    function addOutputsToTx(tx, result) {
        tx.outputs = [];
        tx.outputSatoshis = 0;
        for (let outputIndex = 0; outputIndex < result.vout.length; outputIndex++) {
            const out = result.vout[outputIndex];
            tx.outputSatoshis += out.valueSat;
            let address = null;
            if (out.scriptPubKey && out.scriptPubKey.addresses && out.scriptPubKey.addresses.length === 1) {
                address = out.scriptPubKey.addresses[0];
            }
            tx.outputs.push({
                satoshis: out.valueSat,
                script: out.scriptPubKey.hex,
                scriptAsm: out.scriptPubKey.asm,
                spentTxId: out.spentTxId,
                spentIndex: out.spentIndex,
                spentHeight: out.spentHeight,
                address: address
            });
        }
    }

    if (tx) {
        return tx;
    } else {
        const tx = await this._tryAllClients(async (client) => {
            try {
                const result = await client.getRawTransaction(txid, 1);
                // returns vsize for segwit-positive coins,
                // regular size if segwit is disabled
                const size = result.vsize === null ? result.size : result.vsize;
                const tx = {
                    hex: result.hex,
                    blockHash: result.blockhash,
                    height: result.height ? result.height : -1,
                    blockTimestamp: result.time,
                    version: result.version,
                    hash: txid,
                    locktime: result.locktime,
                    size: size,
                };

                if (result.vin[0] && result.vin[0].coinbase) {
                    tx.coinbase = true;
                }

                addInputsToTx(tx, result);
                addOutputsToTx(tx, result);

                if (!tx.coinbase) {
                    tx.feeSatoshis = tx.inputSatoshis - tx.outputSatoshis;
                } else {
                    tx.feeSatoshis = 0;
                }

                this.transactionDetailedCache.set(txid, tx);

                return tx;
            } catch (e) {
                throw e;
            }

        });
        return tx;
    }
};

Blockchain.prototype.getBestBlockHash = async function () {
    try {
        const bestBlockHash = await this.client.getBestBlockHash();
        return bestBlockHash;
    } catch (e) {
        throw e;
    }
};

Blockchain.prototype.getSpentInfo = async function (options) {
    try {
        const spentInfo = await this.client.getSpentInfo(options);
        return spentInfo;
    } catch (e) {
        if (e.code === -5) {
            return {};
        }
        throw e;
    }
};

/**
 * This will return information about the database in the format:
 * {
 *   version: 110000,
 *   protocolVersion: 70002,
 *   blocks: 151,
 *   timeOffset: 0,
 *   connections: 0,
 *   difficulty: 4.6565423739069247e-10,
 *   testnet: false,
 *   network: 'testnet'
 *   relayFee: 1000,
 *   errors: ''
 * }
 */
Blockchain.prototype.getInfo = async function () {
    try {
        const info = await this.client.getInfo();
        const networkInfo = await this.client.getNetworkInfo();
        const combinedInfo = {
            version: info.version,
            protocolVersion: info.protocolversion,
            blocks: info.blocks,
            timeOffset: info.timeoffset,
            connections: info.connections,
            proxy: info.proxy,
            difficulty: info.difficulty,
            testnet: info.testnet,
            relayFee: info.relayfee,
            errors: info.errors,
            network: this.node.getNetworkName(),
            subversion: networkInfo.subversion,
            localServices: networkInfo.localservices,
        };
        return combinedInfo;
    } catch (e) {
        throw e;
    }
};

Blockchain.prototype.stop = async function () {};

module.exports = Blockchain;
