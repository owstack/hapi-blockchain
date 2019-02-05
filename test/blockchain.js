const EventEmitter = require('events').EventEmitter;
const should = require('chai').should();
const crypto = require('crypto');
const btcLib = require('@owstack/btc-lib');
const keyLib = require('@owstack/key-lib');
const sinon = require('sinon');
const proxyquire = require('proxyquire');

const createError = require('errno').create;
const BlockchainError = createError('BlockchainError');
const RPCError = createError('RPCError', BlockchainError);

const errors = {
    RPCError
};

const Blockchain = require('../lib/blockchain');
const Transaction = btcLib.Transaction;

describe('Blockchain Lib', function () {
    const txhex = '01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0104ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac00000000';

    const baseConfig = {
        currency: 'BTC',
        nodes: []
    };

    describe('@constructor', function () {
        it('will create an instance', function () {
            const bitcoind = new Blockchain(baseConfig);
            should.exist(bitcoind);
        });
        it('will create an instance without `new`', function () {
            const bitcoind = Blockchain(baseConfig);
            should.exist(bitcoind);
        });
        it('will init caches', function () {
            const bitcoind = new Blockchain(baseConfig);
            should.exist(bitcoind.utxosCache);
            should.exist(bitcoind.txidsCache);
            should.exist(bitcoind.balanceCache);
            should.exist(bitcoind.summaryCache);
            should.exist(bitcoind.transactionDetailedCache);

            should.exist(bitcoind.transactionCache);
            should.exist(bitcoind.rawTransactionCache);
            should.exist(bitcoind.blockCache);
            should.exist(bitcoind.rawBlockCache);
            should.exist(bitcoind.blockHeaderCache);
            should.exist(bitcoind.zmqKnownTransactions);
            should.exist(bitcoind.zmqKnownBlocks);
            should.exist(bitcoind.lastTip);
            should.exist(bitcoind.lastTipTimeout);
        });
        it('will init clients', function () {
            const bitcoind = new Blockchain(baseConfig);
            bitcoind.nodes.should.deep.equal([]);
            bitcoind.nodesIndex.should.equal(0);
            bitcoind.nodes.push({client: sinon.stub()});
            should.exist(bitcoind.client);
        });
    });

    describe('#_initDefaults', function () {
        it('will set transaction concurrency', function () {
            const bitcoind = new Blockchain(baseConfig);
            bitcoind._initDefaults({transactionConcurrency: 10});
            bitcoind.transactionConcurrency.should.equal(10);
            bitcoind._initDefaults({});
            bitcoind.transactionConcurrency.should.equal(5);
        });
    });

    describe('#_resetCaches', function () {
        it('will reset LRU caches', function () {
            const bitcoind = new Blockchain(baseConfig);
            const keys = [];
            for (let i = 0; i < 10; i++) {
                keys.push(crypto.randomBytes(32));
                bitcoind.transactionDetailedCache.set(keys[i], {});
                bitcoind.utxosCache.set(keys[i], {});
                bitcoind.txidsCache.set(keys[i], {});
                bitcoind.balanceCache.set(keys[i], {});
                bitcoind.summaryCache.set(keys[i], {});
            }
            bitcoind._resetCaches();
            should.equal(bitcoind.transactionDetailedCache.get(keys[0]), undefined);
            should.equal(bitcoind.utxosCache.get(keys[0]), undefined);
            should.equal(bitcoind.txidsCache.get(keys[0]), undefined);
            should.equal(bitcoind.balanceCache.get(keys[0]), undefined);
            should.equal(bitcoind.summaryCache.get(keys[0]), undefined);
        });
    });

    describe('#_tryAllClients', function () {
        it('will retry for each node client', async function () {
            const bitcoind = new Blockchain(baseConfig);
            bitcoind.tryAllInterval = 1;
            bitcoind.nodes.push({
                client: {
                    getInfo: sinon.stub().rejects(new Error('test'))
                }
            });
            bitcoind.nodes.push({
                client: {
                    getInfo: sinon.stub().rejects(new Error('test'))
                }
            });
            bitcoind.nodes.push({
                client: {
                    getInfo: sinon.stub().resolves({})
                }
            });
            await bitcoind._tryAllClients(function (client) {
                return client.getInfo();
            });
            bitcoind.nodes[0].client.getInfo.callCount.should.equal(1);
            bitcoind.nodes[1].client.getInfo.callCount.should.equal(1);
            bitcoind.nodes[2].client.getInfo.callCount.should.equal(1);
        });
        it('will start using the current node index (round-robin)', async function () {
            const bitcoind = new Blockchain(baseConfig);
            bitcoind.tryAllInterval = 1;
            bitcoind.nodes.push({
                client: {
                    getInfo: sinon.stub().rejects(new Error('2'))
                }
            });
            bitcoind.nodes.push({
                client: {
                    getInfo: sinon.stub().rejects(new Error('3'))
                }
            });
            bitcoind.nodes.push({
                client: {
                    getInfo: sinon.stub().rejects(new Error('1'))
                }
            });
            bitcoind.nodesIndex = 2;
            try {
                await bitcoind._tryAllClients(function (client) {
                    return client.getInfo();
                });
            } catch (e) {
                e.should.be.instanceOf(Error);
                e.message.should.equal('3');
                bitcoind.nodes[0].client.getInfo.callCount.should.equal(1);
                bitcoind.nodes[1].client.getInfo.callCount.should.equal(1);
                bitcoind.nodes[2].client.getInfo.callCount.should.equal(1);
                bitcoind.nodesIndex.should.equal(2);
            }
        });
        it('will get error if all clients fail', async function () {
            const bitcoind = new Blockchain(baseConfig);
            bitcoind.tryAllInterval = 1;
            bitcoind.nodes.push({
                client: {
                    getInfo: sinon.stub().rejects(new Error('test'))
                }
            });
            bitcoind.nodes.push({
                client: {
                    getInfo: sinon.stub().rejects(new Error('test'))
                }
            });
            bitcoind.nodes.push({
                client: {
                    getInfo: sinon.stub().rejects(new Error('test'))
                }
            });
            try {
                await bitcoind._tryAllClients(function (client) {
                    return client.getInfo();
                });
            } catch (e) {
                should.exist(e);
                e.should.be.instanceOf(Error);
                e.message.should.equal('test');
            }
        });
    });

    describe('#_initChain', function () {
        const sandbox = sinon.createSandbox();
        beforeEach(function () {
            sandbox.stub(console, 'log');
        });
        afterEach(function () {
            sandbox.restore();
        });
        it('will set height and genesis buffer', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const genesisBuffer = Buffer.from([]);
            bitcoind.getRawBlock = sinon.stub().resolves(genesisBuffer);
            bitcoind.nodes.push({
                client: {
                    getBestBlockHash: async function () {
                        return 'bestblockhash';
                    },
                    getBlock: async function (hash) {
                        if (hash === 'bestblockhash') {
                            return {
                                height: 5000
                            };
                        }
                    },
                    getBlockHash: async function () {
                        return 'genesishash';
                    }
                }
            });
            await bitcoind._initChain();
            console.log.callCount.should.equal(1);
            bitcoind.getRawBlock.callCount.should.equal(1);
            bitcoind.getRawBlock.args[0][0].should.equal('genesishash');
            bitcoind.height.should.equal(5000);
            bitcoind.genesisBuffer.should.equal(genesisBuffer);
        });
        it('it will handle error from getBestBlockHash', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const getBestBlockHash = sinon.stub().rejects(new Error({code: -1, message: 'error'}));
            bitcoind.nodes.push({
                client: {
                    getBestBlockHash: getBestBlockHash
                }
            });
            try {
                await bitcoind._initChain();
            } catch (e) {
                e.should.be.instanceOf(Error);
            }
        });
        it('it will handle error from getBlock', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const getBestBlockHash = sinon.stub().resolves({});
            const getBlock = sinon.stub().rejects(new Error({code: -1, message: 'error'}));
            bitcoind.nodes.push({
                client: {
                    getBestBlockHash: getBestBlockHash,
                    getBlock: getBlock
                }
            });
            try {
                await bitcoind._initChain();
            } catch (e) {
                e.should.be.instanceOf(Error);
            }
        });
        it('it will handle error from getBlockHash', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const getBestBlockHash = sinon.stub().resolves({});
            const getBlock = sinon.stub().resolves({
                result: {
                    height: 10
                }
            });
            const getBlockHash = sinon.stub().rejects(new Error({code: -1, message: 'error'}));
            bitcoind.nodes.push({
                client: {
                    getBestBlockHash: getBestBlockHash,
                    getBlock: getBlock,
                    getBlockHash: getBlockHash
                }
            });
            try {
                await bitcoind._initChain();
            } catch (e) {
                e.should.be.instanceOf(Error);
            }
        });
        it('it will handle error from getRawBlock', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const getBestBlockHash = sinon.stub().resolves({});
            const getBlock = sinon.stub().resolves({
                result: {
                    height: 10
                }
            });
            const getBlockHash = sinon.stub().resolves({});
            bitcoind.nodes.push({
                client: {
                    getBestBlockHash: getBestBlockHash,
                    getBlock: getBlock,
                    getBlockHash: getBlockHash
                }
            });
            bitcoind.getRawBlock = sinon.stub().rejects(new Error('test'));

            try {
                await bitcoind._initChain();
            } catch (e) {
                e.should.be.instanceOf(Error);
            }
        });
    });

    describe('#_zmqBlockHandler', function () {
        it('will emit block', function (done) {
            const bitcoind = new Blockchain(baseConfig);
            const node = {};
            const message = Buffer.from('00000000002e08fc7ae9a9aa5380e95e2adcdc5752a4a66a7d3a22466bd4e6aa', 'hex');
            bitcoind._rapidProtectedUpdateTip = sinon.stub();
            bitcoind.on('block', function (block) {
                block.should.equal(message);
                done();
            });
            bitcoind._zmqBlockHandler(node, message);
        });
        it('will not emit same block twice', function (done) {
            const bitcoind = new Blockchain(baseConfig);
            const node = {};
            const message = Buffer.from('00000000002e08fc7ae9a9aa5380e95e2adcdc5752a4a66a7d3a22466bd4e6aa', 'hex');
            bitcoind._rapidProtectedUpdateTip = sinon.stub();
            bitcoind.on('block', function (block) {
                block.should.equal(message);
                done();
            });
            bitcoind._zmqBlockHandler(node, message);
            bitcoind._zmqBlockHandler(node, message);
        });
        it('will call function to update tip', function () {
            const bitcoind = new Blockchain(baseConfig);
            const node = {};
            const message = Buffer.from('00000000002e08fc7ae9a9aa5380e95e2adcdc5752a4a66a7d3a22466bd4e6aa', 'hex');
            bitcoind._rapidProtectedUpdateTip = sinon.stub();
            bitcoind._zmqBlockHandler(node, message);
            bitcoind._rapidProtectedUpdateTip.callCount.should.equal(1);
            bitcoind._rapidProtectedUpdateTip.args[0][0].should.equal(node);
            bitcoind._rapidProtectedUpdateTip.args[0][1].should.equal(message);
        });
    });

    describe('#_rapidProtectedUpdateTip', function () {
        it('will limit tip updates with rapid calls', function (done) {
            const bitcoind = new Blockchain(baseConfig);
            let callCount = 0;
            bitcoind._updateTip = function () {
                callCount++;
                callCount.should.be.within(1, 2);
                if (callCount > 1) {
                    done();
                }
            };
            const node = {};
            const message = Buffer.from('00000000002e08fc7ae9a9aa5380e95e2adcdc5752a4a66a7d3a22466bd4e6aa', 'hex');
            let count = 0;
            function repeat() {
                bitcoind._rapidProtectedUpdateTip(node, message);
                count++;
                if (count < 50) {
                    repeat();
                }
            }
            repeat();
        });
    });

    describe('#_updateTip', function () {
        const sandbox = sinon.createSandbox();
        const message = Buffer.from('00000000002e08fc7ae9a9aa5380e95e2adcdc5752a4a66a7d3a22466bd4e6aa', 'hex');
        beforeEach(function () {
            sandbox.stub(console, 'error');
            sandbox.stub(console, 'log');
        });
        afterEach(function () {
            sandbox.restore();
        });
        it('log and emit rpc error from get block', function (done) {
            const bitcoind = new Blockchain(baseConfig);
            bitcoind.syncPercentage = sinon.stub();
            bitcoind.on('error', function (err) {
                err.code.should.equal(-1);
                err.message.should.equal('Test error');
                console.error.callCount.should.equal(1);
                done();
            });
            const err = new Error('Test error');
            err.code = -1;
            const node = {
                client: {
                    getBlock: sinon.stub().rejects(err)
                }
            };
            bitcoind._updateTip(node, message);
        });
        it('emit synced if percentage is 100', function (done) {
            const bitcoind = new Blockchain(baseConfig);
            bitcoind.syncPercentage = sinon.stub().resolves(100);
            bitcoind.on('synced', function () {
                done();
            });
            const node = {
                client: {
                    getBlock: sinon.stub().resolves({height: 123})
                }
            };
            bitcoind._updateTip(node, message);
        });
        it('NOT emit synced if percentage is less than 100', function (done) {
            const bitcoind = new Blockchain(baseConfig);
            bitcoind.syncPercentage = sinon.stub().resolves(99);
            bitcoind.on('synced', function () {
                throw new Error('Synced called');
            });
            const node = {
                client: {
                    getBlock: sinon.stub().resolves({height: 123})
                }
            };
            bitcoind.on('tip', function () {
                console.log.callCount.should.equal(1);
                done();
            });
            bitcoind._updateTip(node, message);

        });
        it('log and emit error from syncPercentage', function (done) {
            const bitcoind = new Blockchain(baseConfig);
            bitcoind.syncPercentage = sinon.stub().rejects(new Error('test'));
            bitcoind.on('error', function (err) {
                console.error.callCount.should.equal(1);
                err.message.should.equal('test');
                done();
            });
            const node = {
                client: {
                    getBlock: sinon.stub().resolves({height: 123})
                }
            };
            bitcoind._updateTip(node, message);
        });
        it('reset caches and set height', function (done) {
            const bitcoind = new Blockchain(baseConfig);
            bitcoind.syncPercentage = sinon.stub().resolves(100);
            bitcoind._resetCaches = sinon.stub();
            bitcoind.on('tip', function (height) {
                bitcoind._resetCaches.callCount.should.equal(1);
                height.should.equal(10);
                bitcoind.height.should.equal(10);
                done();
            });
            const node = {
                client: {
                    getBlock: sinon.stub().resolves({
                        height: 10
                    })
                }
            };
            bitcoind._updateTip(node, message);
        });
        it('will NOT update twice for the same hash', function (done) {
            const bitcoind = new Blockchain(baseConfig);
            bitcoind.syncPercentage = sinon.stub().resolves(100);
            bitcoind._resetCaches = sinon.stub();
            bitcoind.on('tip', function () {
                done();
            });
            const node = {
                client: {
                    getBlock: sinon.stub().resolves({
                        height: 10
                    })
                }
            };
            bitcoind._updateTip(node, message);
            bitcoind._updateTip(node, message);
        });
        it('will not call syncPercentage if node is stopping', function (done) {
            const bitcoind = new Blockchain(baseConfig);
            bitcoind.syncPercentage = sinon.stub();
            bitcoind._resetCaches = sinon.stub();
            bitcoind.node.stopping = true;
            const node = {
                client: {
                    getBlock: sinon.stub().resolves({
                        height: 10
                    })
                }
            };
            bitcoind.on('tip', function () {
                bitcoind.syncPercentage.callCount.should.equal(0);
                done();
            });
            bitcoind._updateTip(node, message);
        });
    });

    describe('#_getAddressesFromTransaction', function () {
        it('will get results using btcLib.Transaction', function () {
            const bitcoind = new Blockchain(baseConfig);
            const wif = 'L2Gkw3kKJ6N24QcDuH4XDqt9cTqsKTVNDGz1CRZhk9cq4auDUbJy';
            const privkey = keyLib.PrivateKey.fromWIF(wif);
            const inputAddress = new btcLib.Address(privkey.publicKey);
            const outputAddress = btcLib.Address('2N2JD6wb56AfK4tfmM6PwdVmoYk2dCKf4Br');
            const tx = btcLib.Transaction();
            tx.from({
                txid: '4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b',
                outputIndex: 0,
                script: btcLib.Script(inputAddress),
                address: inputAddress.toString(),
                satoshis: 5000000000
            });
            tx.to(outputAddress, 5000000000);
            tx.sign(privkey);
            const addresses = bitcoind._getAddressesFromTransaction(tx);
            addresses.length.should.equal(2);
            addresses[0].should.equal(inputAddress.toString());
            addresses[1].should.equal(outputAddress.toString());
        });
        it('will handle non-standard script types', function () {
            const bitcoind = new Blockchain(baseConfig);
            const tx = btcLib.Transaction();
            tx.addInput(btcLib.Transaction.Input({
                prevTxId: '4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b',
                script: btcLib.Script('OP_TRUE'),
                outputIndex: 1,
                output: {
                    script: btcLib.Script('OP_TRUE'),
                    satoshis: 5000000000
                }
            }));
            tx.addOutput(btcLib.Transaction.Output({
                script: btcLib.Script('OP_TRUE'),
                satoshis: 5000000000
            }));
            const addresses = bitcoind._getAddressesFromTransaction(tx);
            addresses.length.should.equal(0);
        });
        it('will handle unparsable script types or missing input script', function () {
            const bitcoind = new Blockchain(baseConfig);
            const tx = btcLib.Transaction();
            tx.addOutput(btcLib.Transaction.Output({
                script: Buffer.from('4c', 'hex'),
                satoshis: 5000000000
            }));
            const addresses = bitcoind._getAddressesFromTransaction(tx);
            addresses.length.should.equal(0);
        });
        it('will return unique values', function () {
            const bitcoind = new Blockchain(baseConfig);
            const tx = btcLib.Transaction();
            const address = btcLib.Address('2N2JD6wb56AfK4tfmM6PwdVmoYk2dCKf4Br');
            tx.addOutput(btcLib.Transaction.Output({
                script: btcLib.Script(address),
                satoshis: 5000000000
            }));
            tx.addOutput(btcLib.Transaction.Output({
                script: btcLib.Script(address),
                satoshis: 5000000000
            }));
            const addresses = bitcoind._getAddressesFromTransaction(tx);
            addresses.length.should.equal(1);
        });
    });

    describe('#_notifyAddressTxidSubscribers', function () {
        it('will emit event if matching addresses', function (done) {
            const bitcoind = new Blockchain(baseConfig);
            const address = '1Cj4UZWnGWAJH1CweTMgPLQMn26WRMfXmo';
            bitcoind._getAddressesFromTransaction = sinon.stub().returns([address]);
            // bitcoind.subscriptions.address[address] = [emitter];
            const txid = '46f24e0c274fc07708b781963576c4c5d5625d926dbb0a17fa865dcd9fe58ea0';
            const transaction = {};
            bitcoind.on('address', function (data) {
                data.address.should.equal(address);
                data.txid.should.equal(txid);
                done();
            });
            sinon.spy(bitcoind, 'emit');
            bitcoind._notifyAddressTxidSubscribers(txid, transaction);
            bitcoind.emit.callCount.should.equal(1);
        });
    });

    describe('#_zmqTransactionHandler', function () {
        it('will emit to subscribers', function (done) {
            const bitcoind = new Blockchain(baseConfig);
            const expectedBuffer = Buffer.from(txhex, 'hex');
            bitcoind.on('tx', function (hex) {
                hex.should.equal(expectedBuffer);
                done();
            });
            const node = {};
            bitcoind._zmqTransactionHandler(node, expectedBuffer);
        });
        it('will NOT emit to subscribers more than once for the same tx', function (done) {
            const bitcoind = new Blockchain(baseConfig);
            const expectedBuffer = Buffer.from(txhex, 'hex');
            bitcoind.on('tx', function () {
                done();
            });
            const node = {};
            bitcoind._zmqTransactionHandler(node, expectedBuffer);
            bitcoind._zmqTransactionHandler(node, expectedBuffer);
        });
        it('will emit "tx" event', function (done) {
            const bitcoind = new Blockchain(baseConfig);
            const expectedBuffer = Buffer.from(txhex, 'hex');
            bitcoind.on('tx', function (buffer) {
                buffer.should.be.instanceof(Buffer);
                buffer.toString('hex').should.equal(expectedBuffer.toString('hex'));
                done();
            });
            const node = {};
            bitcoind._zmqTransactionHandler(node, expectedBuffer);
        });
        it('will NOT emit "tx" event more than once for the same tx', function (done) {
            const bitcoind = new Blockchain(baseConfig);
            const expectedBuffer = Buffer.from(txhex, 'hex');
            bitcoind.on('tx', function () {
                done();
            });
            const node = {};
            bitcoind._zmqTransactionHandler(node, expectedBuffer);
            bitcoind._zmqTransactionHandler(node, expectedBuffer);
        });
    });

    describe('#_checkSyncedAndSubscribeZmqEvents', function () {
        const sandbox = sinon.createSandbox();
        before(function () {
            sandbox.stub(console, 'error');
        });
        after(function () {
            sandbox.restore();
        });
        it('log errors, update tip and subscribe to zmq events', function (done) {
            const bitcoind = new Blockchain(baseConfig);
            bitcoind._updateTip = sinon.stub();
            bitcoind._subscribeZmqEvents = sinon.stub();
            let blockEvents = 0;
            bitcoind.on('block', function () {
                blockEvents++;
            });
            const getBestBlockHash = sinon.stub().resolves('00000000000000001bb82a7f5973618cfd3185ba1ded04dd852a653f92a27c45');
            const err = new Error('Test error');
            err.code = -1;
            getBestBlockHash.onCall(0).rejects(err);
            let progress = 0.90;
            function getProgress() {
                progress = progress + 0.01;
                return progress;
            }
            const info = {};
            Object.defineProperty(info, 'verificationprogress', {
                get: function () {
                    const val = getProgress();
                    return val;
                }
            });
            const getBlockchainInfo = sinon.stub().resolves(info);
            getBlockchainInfo.onCall(0).rejects(err);
            const node = {
                _reindex: true,
                _reindexWait: 1,
                _tipUpdateInterval: 1,
                client: {
                    getBestBlockHash: getBestBlockHash,
                    getBlockchainInfo: getBlockchainInfo
                }
            };
            bitcoind._checkSyncedAndSubscribeZmqEvents(node);
            setTimeout(function () {
                blockEvents.should.equal(11);
                bitcoind._updateTip.callCount.should.equal(11);
                bitcoind._subscribeZmqEvents.callCount.should.equal(1);
                console.error.callCount.should.equal(2);
                done();
            }, 1000);
        });
        it('it will clear interval if node is stopping', function (done) {
            const bitcoind = new Blockchain(baseConfig);
            const err = new Error('error');
            err.code = -1;
            const getBestBlockHash = sinon.stub().rejects(err);
            const node = {
                _tipUpdateInterval: 1,
                client: {
                    getBestBlockHash: getBestBlockHash
                }
            };
            bitcoind._checkSyncedAndSubscribeZmqEvents(node);
            setTimeout(function () {
                bitcoind.node.stopping = true;
                const count = getBestBlockHash.callCount;
                setTimeout(function () {
                    getBestBlockHash.callCount.should.equal(count);
                    done();
                }, 100);
            }, 100);
        });
        it('will not set interval if synced is true', function (done) {
            const bitcoind = new Blockchain(baseConfig);
            bitcoind._updateTip = sinon.stub();
            bitcoind._subscribeZmqEvents = sinon.stub();
            const getBestBlockHash = sinon.stub().resolves('00000000000000001bb82a7f5973618cfd3185ba1ded04dd852a653f92a27c45');
            const info = {
                verificationprogress: 1.00
            };
            const getBlockchainInfo = sinon.stub().resolves(info);
            const node = {
                _tipUpdateInterval: 1,
                client: {
                    getBestBlockHash: getBestBlockHash,
                    getBlockchainInfo: getBlockchainInfo
                }
            };
            bitcoind._checkSyncedAndSubscribeZmqEvents(node);
            setTimeout(function () {
                getBestBlockHash.callCount.should.equal(1);
                getBlockchainInfo.callCount.should.equal(1);
                done();
            }, 200);
        });
    });

    describe('#_subscribeZmqEvents', function () {
        it('will call subscribe on zmq socket', function () {
            const bitcoind = new Blockchain(baseConfig);
            const node = {
                zmqSubSocket: {
                    subscribe: sinon.stub(),
                    on: sinon.stub()
                }
            };
            bitcoind._subscribeZmqEvents(node);
            node.zmqSubSocket.subscribe.callCount.should.equal(2);
            node.zmqSubSocket.subscribe.args[0][0].should.equal('hashblock');
            node.zmqSubSocket.subscribe.args[1][0].should.equal('rawtx');
        });
        it('will call relevant handler for rawtx topics', function (done) {
            const bitcoind = new Blockchain(baseConfig);
            bitcoind._zmqTransactionHandler = sinon.stub();
            const node = {
                zmqSubSocket: new EventEmitter()
            };
            node.zmqSubSocket.subscribe = sinon.stub();
            bitcoind._subscribeZmqEvents(node);
            node.zmqSubSocket.on('message', function () {
                bitcoind._zmqTransactionHandler.callCount.should.equal(1);
                done();
            });
            const topic = Buffer.from('rawtx', 'utf8');
            const message = Buffer.from('abcdef', 'hex');
            node.zmqSubSocket.emit('message', topic, message);
        });
        it('will call relevant handler for hashblock topics', function (done) {
            const bitcoind = new Blockchain(baseConfig);
            bitcoind._zmqBlockHandler = sinon.stub();
            const node = {
                zmqSubSocket: new EventEmitter()
            };
            node.zmqSubSocket.subscribe = sinon.stub();
            bitcoind._subscribeZmqEvents(node);
            node.zmqSubSocket.on('message', function () {
                bitcoind._zmqBlockHandler.callCount.should.equal(1);
                done();
            });
            const topic = Buffer.from('hashblock', 'utf8');
            const message = Buffer.from('abcdef', 'hex');
            node.zmqSubSocket.emit('message', topic, message);
        });
        it('will ignore unknown topic types', function (done) {
            const bitcoind = new Blockchain(baseConfig);
            bitcoind._zmqBlockHandler = sinon.stub();
            bitcoind._zmqTransactionHandler = sinon.stub();
            const node = {
                zmqSubSocket: new EventEmitter()
            };
            node.zmqSubSocket.subscribe = sinon.stub();
            bitcoind._subscribeZmqEvents(node);
            node.zmqSubSocket.on('message', function () {
                bitcoind._zmqBlockHandler.callCount.should.equal(0);
                bitcoind._zmqTransactionHandler.callCount.should.equal(0);
                done();
            });
            const topic = Buffer.from('unknown', 'utf8');
            const message = Buffer.from('abcdef', 'hex');
            node.zmqSubSocket.emit('message', topic, message);
        });
    });

    describe('#_initZmqSubSocket', function () {
        it('will setup zmq socket', function () {
            const socket = new EventEmitter();
            socket.monitor = sinon.stub();
            socket.connect = sinon.stub();
            const socketFunc = function () {
                return socket;
            };
            const Blockchain = proxyquire('../lib/blockchain', {
                zeromq: {
                    socket: socketFunc
                }
            });
            const bitcoind = new Blockchain(baseConfig);
            const node = {};
            bitcoind._initZmqSubSocket(node, 'url');
            node.zmqSubSocket.should.equal(socket);
            socket.connect.callCount.should.equal(1);
            socket.connect.args[0][0].should.equal('url');
            socket.monitor.callCount.should.equal(1);
            socket.monitor.args[0][0].should.equal(500);
            socket.monitor.args[0][1].should.equal(0);
        });
    });

    describe('#_loadTipFromNode', function () {
        const sandbox = sinon.createSandbox();
        beforeEach(function () {
            sandbox.stub(console, 'warn');
        });
        afterEach(function () {
            sandbox.restore();
        });
        it('will give rpc from client getbestblockhash', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const err = new Error('Test error');
            err.code = -1;
            const getBestBlockHash = sinon.stub().rejects(err);
            const node = {
                client: {
                    getBestBlockHash: getBestBlockHash
                }
            };
            let err2;
            try {
                await bitcoind._loadTipFromNode(node);
            } catch (e) {
                err2 = e;
            }
            err2.should.be.instanceof(Error);
            console.warn.callCount.should.equal(0);

        });
        it('will give rpc from client getblock', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const getBestBlockHash = sinon.stub().resolves(
                '00000000000000001bb82a7f5973618cfd3185ba1ded04dd852a653f92a27c45'
            );
            const getBlock = sinon.stub().rejects(new Error('Test error'));
            const node = {
                client: {
                    getBestBlockHash: getBestBlockHash,
                    getBlock: getBlock
                }
            };
            let err;
            try {
                await bitcoind._loadTipFromNode(node);
            } catch (e) {
                err = e;
            }
            getBlock.args[0][0].should.equal('00000000000000001bb82a7f5973618cfd3185ba1ded04dd852a653f92a27c45');
            err.should.be.instanceof(Error);
            console.warn.callCount.should.equal(0);
        });
        it('will log when error is RPC_IN_WARMUP', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const err = new Error('Verifying blocks...');
            err.code = -28;
            const getBestBlockHash = sinon.stub().rejects(err);
            const node = {
                client: {
                    getBestBlockHash: getBestBlockHash
                }
            };
            let err2;
            try {
                await bitcoind._loadTipFromNode(node);
            } catch (e) {
                err2 = e;
            }
            err2.should.be.instanceof(Error);
            console.warn.callCount.should.equal(1);
        });
        it('will set height and emit tip', function (done) {
            const bitcoind = new Blockchain(baseConfig);
            const getBestBlockHash = sinon.stub().resolves(
                '00000000000000001bb82a7f5973618cfd3185ba1ded04dd852a653f92a27c45'
            );
            const getBlock = sinon.stub().resolves({
                height: 100
            });
            const node = {
                client: {
                    getBestBlockHash: getBestBlockHash,
                    getBlock: getBlock
                }
            };
            bitcoind.on('tip', function (height) {
                height.should.equal(100);
                bitcoind.height.should.equal(100);
                done();
            });
            bitcoind._loadTipFromNode(node)
                .then(() => {})
                .catch((e) => {
                    done(e);
                });
        });
    });

    describe('#_connectProcess', function () {
        it('will give error if connecting while shutting down', async function () {
            const bitcoind = new Blockchain(baseConfig);
            bitcoind.node.stopping = true;
            bitcoind.startRetryInterval = 100;
            bitcoind._loadTipFromNode = sinon.stub();
            let err;
            try {
                await bitcoind._connectProcess({});
            } catch (e) {
                err = e;
            }
            err.should.be.instanceof(Error);
            err.message.should.match(/Stopping while trying to connect/);
            bitcoind._loadTipFromNode.callCount.should.equal(0);
        });
        it('will give error from loadTipFromNode after 60 retries', async function () {
            const bitcoind = new Blockchain(baseConfig);
            bitcoind._loadTipFromNode = sinon.stub().rejects(new Error('test'));
            bitcoind.startRetryInterval = 1;
            let err;
            try {
                await bitcoind._connectProcess({});
            } catch (e) {
                err = e;
            }
            err.should.be.instanceof(Error);
            bitcoind._loadTipFromNode.callCount.should.equal(60);
        });
        it('will init zmq/rpc on node', async function () {
            const bitcoind = new Blockchain(baseConfig);
            bitcoind._initZmqSubSocket = sinon.stub();
            bitcoind._subscribeZmqEvents = sinon.stub();
            bitcoind._loadTipFromNode = sinon.stub().resolves();
            let err;
            let node;
            try {
                node = await bitcoind._connectProcess({});
            } catch (e) {
                err = e;
            }
            should.not.exist(err);
            bitcoind._loadTipFromNode.callCount.should.equal(1);
            bitcoind._initZmqSubSocket.callCount.should.equal(1);
            bitcoind._loadTipFromNode.callCount.should.equal(1);
            should.exist(node);
            should.exist(node.client);
        });
    });

    describe('#start', function () {
        const sandbox = sinon.createSandbox();
        beforeEach(function () {
            // sandbox.stub(console, 'log');
        });
        afterEach(function () {
            sandbox.restore();
        });
        it('will give error if "spawn" and "connect" are both not configured', async function () {
            const bitcoind = new Blockchain(baseConfig);
            bitcoind.options = {};
            let err;
            try {
                await bitcoind.start();
            } catch (e) {
                err = e;
            }
            err.should.be.instanceof(Error);
            err.message.should.match(/Blockchain configuration options/);

        });
        it('will give error from connectProcess', async function () {
            const bitcoind = new Blockchain(baseConfig);
            bitcoind._connectProcess = sinon.stub().rejects(new Error('test'));
            bitcoind.options = {
                nodes: [
                    {}
                ]
            };
            let err;
            try {
                await bitcoind.start();
            } catch (e) {
                err = e;
            }

            bitcoind._connectProcess.callCount.should.equal(1);
            err.should.be.instanceof(Error);
            err.message.should.equal('test');
        });
        it('will push node from connectProcess', async function () {
            const bitcoind = new Blockchain(baseConfig);
            bitcoind._initChain = sinon.stub().resolves();
            const nodes = [{}];
            bitcoind._connectProcess = sinon.stub().resolves(nodes);
            bitcoind.options = {
                nodes: [
                    {}
                ]
            };
            let err;
            try {
                await bitcoind.start();
            } catch (e) {
                err = e;
            }

            should.not.exist(err);
            bitcoind._connectProcess.callCount.should.equal(1);
            bitcoind.nodes.length.should.equal(1);
        });
    });

    describe('#isSynced', function () {
        it('will give error from syncPercentage', async function () {
            const bitcoind = new Blockchain(baseConfig);
            bitcoind.syncPercentage = sinon.stub().rejects(new Error('test'));
            let err;
            try {
                await bitcoind.isSynced();
            } catch (e) {
                err = e;
            }

            should.exist(err);
            err.message.should.equal('test');
        });
        it('will give "true" if percentage is 100.00', async function () {
            const bitcoind = new Blockchain(baseConfig);
            bitcoind.syncPercentage = sinon.stub().resolves(100.00);

            let err;
            let synced;
            try {
                synced = await bitcoind.isSynced();
            } catch (e) {
                err = e;
            }
            should.not.exist(err);
            synced.should.equal(true);
        });
        it('will give "true" if percentage is 99.98', async function () {
            const bitcoind = new Blockchain(baseConfig);
            bitcoind.syncPercentage = sinon.stub().resolves(99.98);
            let err;
            let synced;
            try {
                synced = await bitcoind.isSynced();
            } catch (e) {
                err = e;
            }
            should.not.exist(err);
            synced.should.equal(true);
        });
        it('will give "false" if percentage is 99.49', async function () {
            const bitcoind = new Blockchain(baseConfig);
            bitcoind.syncPercentage = sinon.stub().resolves(99.49);
            let err;
            let synced;
            try {
                synced = await bitcoind.isSynced();
            } catch (e) {
                err = e;
            }
            should.not.exist(err);
            synced.should.equal(false);
        });
        it('will give "false" if percentage is 1', async function () {
            const bitcoind = new Blockchain(baseConfig);
            bitcoind.syncPercentage = sinon.stub().resolves(1);
            let err;
            let synced;
            try {
                synced = await bitcoind.isSynced();
            } catch (e) {
                err = e;
            }
            should.not.exist(err);
            synced.should.equal(false);
        });
    });

    describe('#syncPercentage', function () {
        it('will give rpc error', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const err = new RPCError('error');
            err.code = -1;
            const getBlockchainInfo = sinon.stub().rejects(err);
            bitcoind.nodes.push({
                client: {
                    getBlockchainInfo: getBlockchainInfo
                }
            });

            let err2;
            try {
                await bitcoind.syncPercentage();
            } catch (e) {
                err2 = e;
            }

            should.exist(err2);
            err2.should.be.an.instanceof(errors.RPCError);
        });
        it('will call client getInfo and give result', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const getBlockchainInfo = sinon.stub().resolves({
                verificationprogress: '0.983821387'
            });
            bitcoind.nodes.push({
                client: {
                    getBlockchainInfo
                }
            });

            let err;
            let percentage;
            try {
                percentage = await bitcoind.syncPercentage();
            } catch (e) {
                err = e;
            }
            should.not.exist(err);
            percentage.should.equal(98.3821387);
        });
    });

    describe('#_normalizeAddressArg', function () {
        it('will turn single address into array', function () {
            const bitcoind = new Blockchain(baseConfig);
            const args = bitcoind._normalizeAddressArg('address');
            args.should.deep.equal(['address']);
        });
        it('will keep an array as an array', function () {
            const bitcoind = new Blockchain(baseConfig);
            const args = bitcoind._normalizeAddressArg(['address', 'address']);
            args.should.deep.equal(['address', 'address']);
        });
    });

    describe('#getAddressBalance', function () {
        it('will give rpc error', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const err = new Error('Test error');
            err.code = -1;
            bitcoind.nodes.push({
                client: {
                    getAddressBalance: sinon.stub().rejects(err)
                }
            });
            const address = '1Cj4UZWnGWAJH1CweTMgPLQMn26WRMfXmo';
            const options = {};

            let err2;
            try {
                await bitcoind.getAddressBalance(address, options);
            } catch (e) {
                err2 = e;
            }

            err2.should.be.instanceof(Error);
        });
        it('will give balance', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const getAddressBalance = sinon.stub().resolves({
                received: 100000,
                balance: 10000
            });
            bitcoind.nodes.push({client: {getAddressBalance}});
            const address = '1Cj4UZWnGWAJH1CweTMgPLQMn26WRMfXmo';
            const options = {};

            let err;
            let data;
            try {
                data = await bitcoind.getAddressBalance(address, options);
            } catch (e) {
                err = e;
            }
            should.not.exist(err);
            data.balance.should.equal(10000);
            data.received.should.equal(100000);

            let err2;
            let data2;
            try {
                data2 = await bitcoind.getAddressBalance(address, options);
            } catch (e) {
                err2 = e;
            }
            should.not.exist(err2);
            data2.balance.should.equal(10000);
            data2.received.should.equal(100000);
            getAddressBalance.callCount.should.equal(1);
        });
    });

    describe('#getAddressUnspentOutputs', function () {
        it('will give rpc error', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const rpcError = new RPCError('Test error');
            rpcError.code = -1;
            bitcoind.nodes.push({
                client: {
                    getAddressUtxos: sinon.stub().rejects(rpcError)
                }
            });
            const options = {
                queryMempool: false
            };
            const address = '1Cj4UZWnGWAJH1CweTMgPLQMn26WRMfXmo';
            let err;
            try {
                await bitcoind.getAddressUnspentOutputs(address, options);
            } catch (e) {
                err = e;
            }
            should.exist(err);
            err.should.be.instanceof(errors.RPCError);
        });
        it('will give results from client getaddressutxos', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const expectedUtxos = [
                {
                    address: '1Cj4UZWnGWAJH1CweTMgPLQMn26WRMfXmo',
                    txid: '46f24e0c274fc07708b781963576c4c5d5625d926dbb0a17fa865dcd9fe58ea0',
                    outputIndex: 1,
                    script: '76a914f399b4b8894f1153b96fce29f05e6e116eb4c21788ac',
                    satoshis: 7679241,
                    height: 207111
                }
            ];
            bitcoind.nodes.push({
                client: {
                    getAddressUtxos: sinon.stub().resolves(expectedUtxos)
                }
            });
            const options = {
                queryMempool: false
            };
            const address = '1Cj4UZWnGWAJH1CweTMgPLQMn26WRMfXmo';
            let err;
            let utxos;
            try {
                utxos = await bitcoind.getAddressUnspentOutputs(address, options);
            } catch (e) {
                err = e;
            }
            should.not.exist(err);
            utxos.length.should.equal(1);
            utxos.should.deep.equal(expectedUtxos);
        });
        it('will use cache', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const expectedUtxos = [
                {
                    address: '1Cj4UZWnGWAJH1CweTMgPLQMn26WRMfXmo',
                    txid: '46f24e0c274fc07708b781963576c4c5d5625d926dbb0a17fa865dcd9fe58ea0',
                    outputIndex: 1,
                    script: '76a914f399b4b8894f1153b96fce29f05e6e116eb4c21788ac',
                    satoshis: 7679241,
                    height: 207111
                }
            ];
            const getAddressUtxos = sinon.stub().resolves(expectedUtxos);
            bitcoind.nodes.push({
                client: {
                    getAddressUtxos: getAddressUtxos
                }
            });
            const options = {
                queryMempool: false
            };
            const address = '1Cj4UZWnGWAJH1CweTMgPLQMn26WRMfXmo';
            let err;
            let utxos;
            try {
                utxos = await bitcoind.getAddressUnspentOutputs(address, options);
            } catch (e) {
                err = e;
            }
            should.not.exist(err);
            utxos.length.should.equal(1);
            utxos.should.deep.equal(expectedUtxos);
            getAddressUtxos.callCount.should.equal(1);
            let err2;
            let utxos2;
            try {
                utxos2 = await bitcoind.getAddressUnspentOutputs(address, options);
            } catch (e) {
                err2 = e;
            }
            should.not.exist(err2);
            utxos2.length.should.equal(1);
            utxos2.should.deep.equal(expectedUtxos);
            getAddressUtxos.callCount.should.equal(1);

        });
        it('will update with mempool results', async function () {
            const deltas = [
                {
                    txid: 'e9dcf22807db77ac0276b03cc2d3a8b03c4837db8ac6650501ef45af1c807cce',
                    satoshis: -7679241,
                    address: '1Cj4UZWnGWAJH1CweTMgPLQMn26WRMfXmo',
                    index: 0,
                    timestamp: 1461342707725,
                    prevtxid: '46f24e0c274fc07708b781963576c4c5d5625d926dbb0a17fa865dcd9fe58ea0',
                    prevout: 1
                },
                {
                    txid: 'f637384e9f81f18767ea50e00bce58fc9848b6588a1130529eebba22a410155f',
                    satoshis: 100000,
                    address: '1Cj4UZWnGWAJH1CweTMgPLQMn26WRMfXmo',
                    index: 0,
                    timestamp: 1461342833133
                },
                {
                    txid: 'f71bccef3a8f5609c7f016154922adbfe0194a96fb17a798c24077c18d0a9345',
                    satoshis: 400000,
                    address: '1Cj4UZWnGWAJH1CweTMgPLQMn26WRMfXmo',
                    index: 1,
                    timestamp: 1461342954813
                }
            ];
            const bitcoind = new Blockchain(baseConfig);
            const confirmedUtxos = [
                {
                    address: '1Cj4UZWnGWAJH1CweTMgPLQMn26WRMfXmo',
                    txid: '46f24e0c274fc07708b781963576c4c5d5625d926dbb0a17fa865dcd9fe58ea0',
                    outputIndex: 1,
                    script: '76a914f399b4b8894f1153b96fce29f05e6e116eb4c21788ac',
                    satoshis: 7679241,
                    height: 207111
                }
            ];
            const expectedUtxos = [
                {
                    address: '1Cj4UZWnGWAJH1CweTMgPLQMn26WRMfXmo',
                    outputIndex: 1,
                    satoshis: 400000,
                    script: '76a914809dc14496f99b6deb722cf46d89d22f4beb8efd88ac',
                    timestamp: 1461342954813,
                    txid: 'f71bccef3a8f5609c7f016154922adbfe0194a96fb17a798c24077c18d0a9345'
                },
                {
                    address: '1Cj4UZWnGWAJH1CweTMgPLQMn26WRMfXmo',
                    outputIndex: 0,
                    satoshis: 100000,
                    script: '76a914809dc14496f99b6deb722cf46d89d22f4beb8efd88ac',
                    timestamp: 1461342833133,
                    txid: 'f637384e9f81f18767ea50e00bce58fc9848b6588a1130529eebba22a410155f'
                }
            ];
            bitcoind.nodes.push({
                client: {
                    getAddressUtxos: sinon.stub().resolves(confirmedUtxos),
                    getAddressMempool: sinon.stub().resolves(deltas)
                }
            });
            const options = {
                queryMempool: true
            };
            const address = '1Cj4UZWnGWAJH1CweTMgPLQMn26WRMfXmo';
            let err;
            let utxos;
            try {
                utxos = await bitcoind.getAddressUnspentOutputs(address, options);
            } catch (e) {
                err = e;
            }
            should.not.exist(err);
            utxos.length.should.equal(2);
            utxos.should.deep.equal(expectedUtxos);
        });
        it('will update with mempool results with multiple outputs', async function () {
            const deltas = [
                {
                    txid: 'e9dcf22807db77ac0276b03cc2d3a8b03c4837db8ac6650501ef45af1c807cce',
                    satoshis: -7679241,
                    address: '1Cj4UZWnGWAJH1CweTMgPLQMn26WRMfXmo',
                    index: 0,
                    timestamp: 1461342707725,
                    prevtxid: '46f24e0c274fc07708b781963576c4c5d5625d926dbb0a17fa865dcd9fe58ea0',
                    prevout: 1
                },
                {
                    txid: 'e9dcf22807db77ac0276b03cc2d3a8b03c4837db8ac6650501ef45af1c807cce',
                    satoshis: -7679241,
                    address: '1Cj4UZWnGWAJH1CweTMgPLQMn26WRMfXmo',
                    index: 1,
                    timestamp: 1461342707725,
                    prevtxid: '46f24e0c274fc07708b781963576c4c5d5625d926dbb0a17fa865dcd9fe58ea0',
                    prevout: 2
                }
            ];
            const bitcoind = new Blockchain(baseConfig);
            const confirmedUtxos = [
                {
                    address: '1Cj4UZWnGWAJH1CweTMgPLQMn26WRMfXmo',
                    txid: '46f24e0c274fc07708b781963576c4c5d5625d926dbb0a17fa865dcd9fe58ea0',
                    outputIndex: 1,
                    script: '76a914f399b4b8894f1153b96fce29f05e6e116eb4c21788ac',
                    satoshis: 7679241,
                    height: 207111
                },
                {
                    address: '1Cj4UZWnGWAJH1CweTMgPLQMn26WRMfXmo',
                    txid: '46f24e0c274fc07708b781963576c4c5d5625d926dbb0a17fa865dcd9fe58ea0',
                    outputIndex: 2,
                    script: '76a914f399b4b8894f1153b96fce29f05e6e116eb4c21788ac',
                    satoshis: 7679241,
                    height: 207111
                }
            ];
            bitcoind.nodes.push({
                client: {
                    getAddressUtxos: sinon.stub().resolves(confirmedUtxos),
                    getAddressMempool: sinon.stub().resolves(deltas)
                }
            });
            const options = {
                queryMempool: true
            };
            const address = '1Cj4UZWnGWAJH1CweTMgPLQMn26WRMfXmo';
            let err;
            let utxos;
            try {
                utxos = await bitcoind.getAddressUnspentOutputs(address, options);
            } catch (e) {
                err = e;
            }
            should.not.exist(err);
            utxos.length.should.equal(0);
        });
        it('three confirmed utxos -> one utxo after mempool', async function () {
            const deltas = [
                {
                    txid: 'e9dcf22807db77ac0276b03cc2d3a8b03c4837db8ac6650501ef45af1c807cce',
                    satoshis: -7679241,
                    address: '1Cj4UZWnGWAJH1CweTMgPLQMn26WRMfXmo',
                    index: 0,
                    timestamp: 1461342707725,
                    prevtxid: '46f24e0c274fc07708b781963576c4c5d5625d926dbb0a17fa865dcd9fe58ea0',
                    prevout: 0
                },
                {
                    txid: 'e9dcf22807db77ac0276b03cc2d3a8b03c4837db8ac6650501ef45af1c807cce',
                    satoshis: -7679241,
                    address: '1Cj4UZWnGWAJH1CweTMgPLQMn26WRMfXmo',
                    index: 0,
                    timestamp: 1461342707725,
                    prevtxid: '46f24e0c274fc07708b781963576c4c5d5625d926dbb0a17fa865dcd9fe58ea0',
                    prevout: 1
                },
                {
                    txid: 'e9dcf22807db77ac0276b03cc2d3a8b03c4837db8ac6650501ef45af1c807cce',
                    satoshis: -7679241,
                    address: '1Cj4UZWnGWAJH1CweTMgPLQMn26WRMfXmo',
                    index: 1,
                    timestamp: 1461342707725,
                    prevtxid: '46f24e0c274fc07708b781963576c4c5d5625d926dbb0a17fa865dcd9fe58ea0',
                    prevout: 2
                },
                {
                    txid: 'e9dcf22807db77ac0276b03cc2d3a8b03c4837db8ac6650501ef45af1c807cce',
                    satoshis: 100000,
                    address: '1Cj4UZWnGWAJH1CweTMgPLQMn26WRMfXmo',
                    index: 1,
                    script: '76a914809dc14496f99b6deb722cf46d89d22f4beb8efd88ac',
                    timestamp: 1461342833133
                }
            ];
            const bitcoind = new Blockchain(baseConfig);
            const confirmedUtxos = [
                {
                    address: '1Cj4UZWnGWAJH1CweTMgPLQMn26WRMfXmo',
                    txid: '46f24e0c274fc07708b781963576c4c5d5625d926dbb0a17fa865dcd9fe58ea0',
                    outputIndex: 0,
                    script: '76a914f399b4b8894f1153b96fce29f05e6e116eb4c21788ac',
                    satoshis: 7679241,
                    height: 207111
                },
                {
                    address: '1Cj4UZWnGWAJH1CweTMgPLQMn26WRMfXmo',
                    txid: '46f24e0c274fc07708b781963576c4c5d5625d926dbb0a17fa865dcd9fe58ea0',
                    outputIndex: 1,
                    script: '76a914f399b4b8894f1153b96fce29f05e6e116eb4c21788ac',
                    satoshis: 7679241,
                    height: 207111
                },
                {
                    address: '1Cj4UZWnGWAJH1CweTMgPLQMn26WRMfXmo',
                    txid: '46f24e0c274fc07708b781963576c4c5d5625d926dbb0a17fa865dcd9fe58ea0',
                    outputIndex: 2,
                    script: '76a914f399b4b8894f1153b96fce29f05e6e116eb4c21788ac',
                    satoshis: 7679241,
                    height: 207111
                }
            ];
            bitcoind.nodes.push({
                client: {
                    getAddressUtxos: sinon.stub().resolves(confirmedUtxos),
                    getAddressMempool: sinon.stub().resolves(deltas)
                }
            });
            const options = {
                queryMempool: true
            };
            const address = '1Cj4UZWnGWAJH1CweTMgPLQMn26WRMfXmo';
            let err;
            let utxos;
            try {
                utxos = await bitcoind.getAddressUnspentOutputs(address, options);
            } catch (e) {
                err = e;
            }
            should.not.exist(err);
            utxos.length.should.equal(1);
        });
        it('spending utxos in the mempool', async function () {
            const deltas = [
                {
                    txid: '46f24e0c274fc07708b781963576c4c5d5625d926dbb0a17fa865dcd9fe58ea0',
                    satoshis: 7679241,
                    address: '1Cj4UZWnGWAJH1CweTMgPLQMn26WRMfXmo',
                    index: 0,
                    timestamp: 1461342707724
                },
                {
                    txid: '46f24e0c274fc07708b781963576c4c5d5625d926dbb0a17fa865dcd9fe58ea0',
                    satoshis: 7679241,
                    address: '1Cj4UZWnGWAJH1CweTMgPLQMn26WRMfXmo',
                    index: 1,
                    timestamp: 1461342707724
                },
                {
                    txid: '46f24e0c274fc07708b781963576c4c5d5625d926dbb0a17fa865dcd9fe58ea0',
                    satoshis: 7679241,
                    address: '1Cj4UZWnGWAJH1CweTMgPLQMn26WRMfXmo',
                    timestamp: 1461342707724,
                    index: 2,
                },
                {
                    txid: 'e9dcf22807db77ac0276b03cc2d3a8b03c4837db8ac6650501ef45af1c807cce',
                    satoshis: -7679241,
                    address: '1Cj4UZWnGWAJH1CweTMgPLQMn26WRMfXmo',
                    index: 0,
                    timestamp: 1461342707725,
                    prevtxid: '46f24e0c274fc07708b781963576c4c5d5625d926dbb0a17fa865dcd9fe58ea0',
                    prevout: 0
                },
                {
                    txid: 'e9dcf22807db77ac0276b03cc2d3a8b03c4837db8ac6650501ef45af1c807cce',
                    satoshis: -7679241,
                    address: '1Cj4UZWnGWAJH1CweTMgPLQMn26WRMfXmo',
                    index: 0,
                    timestamp: 1461342707725,
                    prevtxid: '46f24e0c274fc07708b781963576c4c5d5625d926dbb0a17fa865dcd9fe58ea0',
                    prevout: 1
                },
                {
                    txid: 'e9dcf22807db77ac0276b03cc2d3a8b03c4837db8ac6650501ef45af1c807cce',
                    satoshis: -7679241,
                    address: '1Cj4UZWnGWAJH1CweTMgPLQMn26WRMfXmo',
                    index: 1,
                    timestamp: 1461342707725,
                    prevtxid: '46f24e0c274fc07708b781963576c4c5d5625d926dbb0a17fa865dcd9fe58ea0',
                    prevout: 2
                },
                {
                    txid: 'e9dcf22807db77ac0276b03cc2d3a8b03c4837db8ac6650501ef45af1c807cce',
                    satoshis: 100000,
                    address: '1Cj4UZWnGWAJH1CweTMgPLQMn26WRMfXmo',
                    index: 1,
                    timestamp: 1461342833133
                }
            ];
            const bitcoind = new Blockchain(baseConfig);
            const confirmedUtxos = [];
            bitcoind.nodes.push({
                client: {
                    getAddressUtxos: sinon.stub().resolves(confirmedUtxos),
                    getAddressMempool: sinon.stub().resolves(deltas)
                }
            });
            const options = {
                queryMempool: true
            };
            const address = '1Cj4UZWnGWAJH1CweTMgPLQMn26WRMfXmo';
            let err;
            let utxos;
            try {
                utxos = await bitcoind.getAddressUnspentOutputs(address, options);
            } catch (e) {
                err = e;
            }
            should.not.exist(err);
            utxos.length.should.equal(1);
            utxos[0].address.should.equal(address);
            utxos[0].txid.should.equal('e9dcf22807db77ac0276b03cc2d3a8b03c4837db8ac6650501ef45af1c807cce');
            utxos[0].outputIndex.should.equal(1);
            utxos[0].script.should.equal('76a914809dc14496f99b6deb722cf46d89d22f4beb8efd88ac');
            utxos[0].timestamp.should.equal(1461342833133);

        });
        it('will update with mempool results spending zero value output (likely never to happen)', async function () {
            const deltas = [
                {
                    txid: 'e9dcf22807db77ac0276b03cc2d3a8b03c4837db8ac6650501ef45af1c807cce',
                    satoshis: 0,
                    address: '1Cj4UZWnGWAJH1CweTMgPLQMn26WRMfXmo',
                    index: 0,
                    timestamp: 1461342707725,
                    prevtxid: '46f24e0c274fc07708b781963576c4c5d5625d926dbb0a17fa865dcd9fe58ea0',
                    prevout: 1
                }
            ];
            const bitcoind = new Blockchain(baseConfig);
            const confirmedUtxos = [
                {
                    address: '1Cj4UZWnGWAJH1CweTMgPLQMn26WRMfXmo',
                    txid: '46f24e0c274fc07708b781963576c4c5d5625d926dbb0a17fa865dcd9fe58ea0',
                    outputIndex: 1,
                    script: '76a914f399b4b8894f1153b96fce29f05e6e116eb4c21788ac',
                    satoshis: 0,
                    height: 207111
                }
            ];
            bitcoind.nodes.push({
                client: {
                    getAddressUtxos: sinon.stub().resolves(confirmedUtxos),
                    getAddressMempool: sinon.stub().resolves(deltas)
                }
            });
            const options = {
                queryMempool: true
            };
            const address = '1Cj4UZWnGWAJH1CweTMgPLQMn26WRMfXmo';
            let err;
            let utxos;
            try {
                utxos = await bitcoind.getAddressUnspentOutputs(address, options);
            } catch (e) {
                err = e;
            }
            should.not.exist(err);
            utxos.length.should.equal(0);
        });
        it('will not filter results if mempool is not spending', async function () {
            const deltas = [
                {
                    txid: 'e9dcf22807db77ac0276b03cc2d3a8b03c4837db8ac6650501ef45af1c807cce',
                    satoshis: 10000,
                    address: '1Cj4UZWnGWAJH1CweTMgPLQMn26WRMfXmo',
                    index: 0,
                    timestamp: 1461342707725
                }
            ];
            const bitcoind = new Blockchain(baseConfig);
            const confirmedUtxos = [
                {
                    address: '1Cj4UZWnGWAJH1CweTMgPLQMn26WRMfXmo',
                    txid: '46f24e0c274fc07708b781963576c4c5d5625d926dbb0a17fa865dcd9fe58ea0',
                    outputIndex: 1,
                    script: '76a914f399b4b8894f1153b96fce29f05e6e116eb4c21788ac',
                    satoshis: 0,
                    height: 207111
                }
            ];
            bitcoind.nodes.push({
                client: {
                    getAddressUtxos: sinon.stub().resolves(confirmedUtxos),
                    getAddressMempool: sinon.stub().resolves(deltas)
                }
            });
            const options = {
                queryMempool: true
            };
            const address = '1Cj4UZWnGWAJH1CweTMgPLQMn26WRMfXmo';
            let err;
            let utxos;
            try {
                utxos = await bitcoind.getAddressUnspentOutputs(address, options);
            } catch (e) {
                err = e;
            }
            should.not.exist(err);
            utxos.length.should.equal(2);
        });
        it('it will handle error from getAddressMempool', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const rpcError = new RPCError('test');
            rpcError.code = -1;
            bitcoind.nodes.push({
                client: {
                    getAddressMempool: sinon.stub().rejects(rpcError)
                }
            });
            const options = {
                queryMempool: true
            };
            const address = '1Cj4UZWnGWAJH1CweTMgPLQMn26WRMfXmo';
            let err;
            try {
                await bitcoind.getAddressUnspentOutputs(address, options);
            } catch (e) {
                err = e;
            }
            err.should.be.instanceOf(Error);
        });
        it('should set query mempool if undefined', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const rpcError = new RPCError('test');
            const getAddressMempool = sinon.stub().rejects(rpcError);
            bitcoind.nodes.push({
                client: {
                    getAddressMempool: getAddressMempool
                }
            });
            const options = {};
            const address = '1Cj4UZWnGWAJH1CweTMgPLQMn26WRMfXmo';
            let err;
            try {
                await bitcoind.getAddressUnspentOutputs(address, options);
            } catch (e) {
                err = e;
            }
            should.exist(err);
            getAddressMempool.callCount.should.equal(1);
        });
    });

    describe('#_getBalanceFromMempool', function () {
        it('will sum satoshis', function () {
            const bitcoind = new Blockchain(baseConfig);
            const deltas = [
                {
                    satoshis: -1000,
                },
                {
                    satoshis: 2000,
                },
                {
                    satoshis: -10,
                }
            ];
            const sum = bitcoind._getBalanceFromMempool(deltas);
            sum.should.equal(990);
        });
    });

    describe('#_getTxidsFromMempool', function () {
        it('will filter to txids', function () {
            const bitcoind = new Blockchain(baseConfig);
            const deltas = [
                {
                    txid: 'txid0',
                },
                {
                    txid: 'txid1',
                },
                {
                    txid: 'txid2',
                }
            ];
            const txids = bitcoind._getTxidsFromMempool(deltas);
            txids.length.should.equal(3);
            txids[0].should.equal('txid0');
            txids[1].should.equal('txid1');
            txids[2].should.equal('txid2');
        });
        it('will not include duplicates', function () {
            const bitcoind = new Blockchain(baseConfig);
            const deltas = [
                {
                    txid: 'txid0',
                },
                {
                    txid: 'txid0',
                },
                {
                    txid: 'txid1',
                }
            ];
            const txids = bitcoind._getTxidsFromMempool(deltas);
            txids.length.should.equal(2);
            txids[0].should.equal('txid0');
            txids[1].should.equal('txid1');
        });
    });

    describe('#_getHeightRangeQuery', function () {
        it('will detect range query', function () {
            const bitcoind = new Blockchain(baseConfig);
            const options = {
                start: 20,
                end: 0
            };
            const rangeQuery = bitcoind._getHeightRangeQuery(options);
            rangeQuery.should.equal(true);
        });
        it('will get range properties', function () {
            const bitcoind = new Blockchain(baseConfig);
            const options = {
                start: 20,
                end: 0
            };
            const clone = {};
            bitcoind._getHeightRangeQuery(options, clone);
            clone.end.should.equal(20);
            clone.start.should.equal(0);
        });
        it('will throw error with invalid range', function () {
            const bitcoind = new Blockchain(baseConfig);
            const options = {
                start: 0,
                end: 20
            };
            (function () {
                bitcoind._getHeightRangeQuery(options);
            }).should.throw('"end" is expected');
        });
    });

    describe('#getAddressTxids', function () {
        it('will give error from _getHeightRangeQuery', async function () {
            const bitcoind = new Blockchain(baseConfig);
            bitcoind._getHeightRangeQuery = sinon.stub().throws(new Error('test'));
            let err;
            try {
                await bitcoind.getAddressTxids('address', {});
            } catch (e) {
                err = e;
            }
            err.should.be.instanceOf(Error);
            err.message.should.equal('test');
        });
        it('will give rpc error from mempool query', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const rpcError = new RPCError('Test error');
            rpcError.code = -1;
            bitcoind.nodes.push({
                client: {
                    getAddressMempool: sinon.stub().rejects(rpcError)
                }
            });
            const address = '1Cj4UZWnGWAJH1CweTMgPLQMn26WRMfXmo';
            let err;
            try {
                await bitcoind.getAddressTxids(address, {});
            } catch (e) {
                err = e;
            }
            should.exist(err);
            err.should.be.instanceof(errors.RPCError);
        });
        it('will give rpc error from txids query', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const rpcError = new RPCError('Test error');
            rpcError.code = -1;
            bitcoind.nodes.push({
                client: {
                    getAddressTxids: sinon.stub().rejects(rpcError)
                }
            });
            const options = {
                queryMempool: false
            };
            const address = '1Cj4UZWnGWAJH1CweTMgPLQMn26WRMfXmo';
            let err;
            try {
                await bitcoind.getAddressTxids(address, options);
            } catch (e) {
                err = e;
            }
            should.exist(err);
            err.should.be.instanceof(errors.RPCError);
        });
        it('will get txid results', async function () {
            const expectedTxids = [
                'e9dcf22807db77ac0276b03cc2d3a8b03c4837db8ac6650501ef45af1c807cce',
                'f637384e9f81f18767ea50e00bce58fc9848b6588a1130529eebba22a410155f',
                'f3c1ba3ef86a0420d6102e40e2cfc8682632ab95d09d86a27f5d466b9fa9da47',
                '56fafeb01961831b926558d040c246b97709fd700adcaa916541270583e8e579',
                'bc992ad772eb02864db07ef248d31fb3c6826d25f1153ebf8c79df9b7f70fcf2',
                'f71bccef3a8f5609c7f016154922adbfe0194a96fb17a798c24077c18d0a9345',
                'f35e7e2a2334e845946f3eaca76890d9a68f4393ccc9fe37a0c2fb035f66d2e9',
                'edc080f2084eed362aa488ccc873a24c378dc0979aa29b05767517b70569414a',
                'ed11a08e3102f9610bda44c80c46781d97936a4290691d87244b1b345b39a693',
                'ec94d845c603f292a93b7c829811ac624b76e52b351617ca5a758e9d61a11681'
            ];
            const bitcoind = new Blockchain(baseConfig);
            bitcoind.nodes.push({
                client: {
                    getAddressTxids: sinon.stub().resolves(expectedTxids.reverse())
                }
            });
            const options = {
                queryMempool: false
            };
            const address = '1Cj4UZWnGWAJH1CweTMgPLQMn26WRMfXmo';
            let err;
            let txids;
            try {
                txids = await bitcoind.getAddressTxids(address, options);
            } catch (e) {
                err = e;
            }
            should.not.exist(err);
            txids.length.should.equal(expectedTxids.length);
            txids.should.deep.equal(expectedTxids);
        });
        it('will get txid results from cache', async function () {
            const expectedTxids = [
                'e9dcf22807db77ac0276b03cc2d3a8b03c4837db8ac6650501ef45af1c807cce'
            ];
            const bitcoind = new Blockchain(baseConfig);
            const getAddressTxids = sinon.stub().resolves(expectedTxids.reverse());
            bitcoind.nodes.push({
                client: {
                    getAddressTxids: getAddressTxids
                }
            });
            const options = {
                queryMempool: false
            };
            const address = '1Cj4UZWnGWAJH1CweTMgPLQMn26WRMfXmo';
            let err;
            let txids;
            try {
                txids = await bitcoind.getAddressTxids(address, options);
            } catch (e) {
                err = e;
            }
            should.not.exist(err);
            getAddressTxids.callCount.should.equal(1);
            txids.should.deep.equal(expectedTxids);

            let err2;
            let txids2;
            try {
                txids2 = await bitcoind.getAddressTxids(address, options);
            } catch (e) {
                err2 = e;
            }
            should.not.exist(err2);
            getAddressTxids.callCount.should.equal(1);
            txids2.should.deep.equal(expectedTxids);
        });
        it('will get txid results WITHOUT cache if rangeQuery and exclude mempool', async function () {
            const expectedTxids = [
                'e9dcf22807db77ac0276b03cc2d3a8b03c4837db8ac6650501ef45af1c807cce'
            ];
            const bitcoind = new Blockchain(baseConfig);
            const getAddressMempool = sinon.stub();
            const getAddressTxids = sinon.stub().resolves(expectedTxids.reverse());
            bitcoind.nodes.push({
                client: {
                    getAddressTxids: getAddressTxids,
                    getAddressMempool: getAddressMempool
                }
            });
            const options = {
                queryMempool: true, // start and end will exclude mempool
                start: 4,
                end: 2
            };
            const address = '1Cj4UZWnGWAJH1CweTMgPLQMn26WRMfXmo';
            let err;
            let txids;
            try {
                txids = await bitcoind.getAddressTxids(address, options);
            } catch (e) {
                err = e;
            }
            should.not.exist(err);
            getAddressTxids.callCount.should.equal(1);
            getAddressMempool.callCount.should.equal(0);
            txids.should.deep.equal(expectedTxids);

            let err2;
            let txids2;
            try {
                txids2 = await bitcoind.getAddressTxids(address, options);
            } catch (e) {
                err2 = e;
            }
            should.not.exist(err2);
            getAddressTxids.callCount.should.equal(2);
            getAddressMempool.callCount.should.equal(0);
            txids2.should.deep.equal(expectedTxids);

        });
        it('will get txid results from cache and live mempool', async function () {
            const expectedTxids = [
                'e9dcf22807db77ac0276b03cc2d3a8b03c4837db8ac6650501ef45af1c807cce'
            ];
            const bitcoind = new Blockchain(baseConfig);
            const getAddressTxids = sinon.stub().resolves(expectedTxids.reverse());
            const getAddressMempool = sinon.stub().resolves([
                {
                    txid: 'bc992ad772eb02864db07ef248d31fb3c6826d25f1153ebf8c79df9b7f70fcf2'
                },
                {
                    txid: 'f71bccef3a8f5609c7f016154922adbfe0194a96fb17a798c24077c18d0a9345'
                },
                {
                    txid: 'f35e7e2a2334e845946f3eaca76890d9a68f4393ccc9fe37a0c2fb035f66d2e9'
                }
            ]);
            bitcoind.nodes.push({
                client: {
                    getAddressTxids: getAddressTxids,
                    getAddressMempool: getAddressMempool
                }
            });
            const address = '1Cj4UZWnGWAJH1CweTMgPLQMn26WRMfXmo';
            const options = {queryMempool: false};
            let err;
            let txids;
            try {
                txids = await bitcoind.getAddressTxids(address, options);
            } catch (e) {
                err = e;
            }
            should.not.exist(err);
            getAddressTxids.callCount.should.equal(1);
            txids.should.deep.equal(expectedTxids);

            const options2 = {queryMempool: true};
            let err2;
            let txids2;
            try {
                txids2 = await bitcoind.getAddressTxids(address, options2);
            } catch (e) {
                err2 = e;
            }
            should.not.exist(err2);
            getAddressTxids.callCount.should.equal(1);
            txids2.should.deep.equal([
                'f35e7e2a2334e845946f3eaca76890d9a68f4393ccc9fe37a0c2fb035f66d2e9', // mempool
                'f71bccef3a8f5609c7f016154922adbfe0194a96fb17a798c24077c18d0a9345', // mempool
                'bc992ad772eb02864db07ef248d31fb3c6826d25f1153ebf8c79df9b7f70fcf2', // mempool
                'e9dcf22807db77ac0276b03cc2d3a8b03c4837db8ac6650501ef45af1c807cce' // confirmed
            ]);

            const options3 = {queryMempoolOnly: true};
            let err3;
            let txids3;
            try {
                txids3 = await bitcoind.getAddressTxids(address, options3);
            } catch (e) {
                err3 = e;
            }
            should.not.exist(err3);
            getAddressTxids.callCount.should.equal(1);
            txids3.should.deep.equal([
                'f35e7e2a2334e845946f3eaca76890d9a68f4393ccc9fe37a0c2fb035f66d2e9', // mempool
                'f71bccef3a8f5609c7f016154922adbfe0194a96fb17a798c24077c18d0a9345', // mempool
                'bc992ad772eb02864db07ef248d31fb3c6826d25f1153ebf8c79df9b7f70fcf2', // mempool
            ]);
        });
    });

    describe('#_getConfirmationDetail', function () {
        const sandbox = sinon.createSandbox();
        beforeEach(function () {
            sandbox.stub(console, 'warn');
        });
        afterEach(function () {
            sandbox.restore();
        });
        it('should get 0 confirmation', function () {
            const tx = new Transaction(txhex);
            tx.height = -1;
            const bitcoind = new Blockchain(baseConfig);
            bitcoind.height = 10;
            const confirmations = bitcoind._getConfirmationsDetail(tx);
            confirmations.should.equal(0);
        });
        it('should get 1 confirmation', function () {
            const tx = new Transaction(txhex);
            tx.height = 10;
            const bitcoind = new Blockchain(baseConfig);
            bitcoind.height = 10;
            const confirmations = bitcoind._getConfirmationsDetail(tx);
            confirmations.should.equal(1);
        });
        it('should get 2 confirmation', function () {
            const bitcoind = new Blockchain(baseConfig);
            const tx = new Transaction(txhex);
            bitcoind.height = 11;
            tx.height = 10;
            const confirmations = bitcoind._getConfirmationsDetail(tx);
            confirmations.should.equal(2);
        });
        it('should get 0 confirmation with overflow', function () {
            const bitcoind = new Blockchain(baseConfig);
            const tx = new Transaction(txhex);
            bitcoind.height = 3;
            tx.height = 10;
            const confirmations = bitcoind._getConfirmationsDetail(tx);
            console.warn.callCount.should.equal(1);
            confirmations.should.equal(0);
        });
        it('should get 1000 confirmation', function () {
            const bitcoind = new Blockchain(baseConfig);
            const tx = new Transaction(txhex);
            bitcoind.height = 1000;
            tx.height = 1;
            const confirmations = bitcoind._getConfirmationsDetail(tx);
            confirmations.should.equal(1000);
        });
    });

    describe('#_getAddressDetailsForInput', function () {
        it('will return if missing an address', function () {
            const bitcoind = new Blockchain(baseConfig);
            const result = {};
            bitcoind._getAddressDetailsForInput({}, 0, result, []);
            should.not.exist(result.addresses);
            should.not.exist(result.satoshis);
        });
        it('will only add address if it matches', function () {
            const bitcoind = new Blockchain(baseConfig);
            const result = {};
            bitcoind._getAddressDetailsForInput({
                address: 'address1'
            }, 0, result, ['address2']);
            should.not.exist(result.addresses);
            should.not.exist(result.satoshis);
        });
        it('will instantiate if outputIndexes not defined', function () {
            const bitcoind = new Blockchain(baseConfig);
            const result = {
                addresses: {}
            };
            bitcoind._getAddressDetailsForInput({
                address: 'address1'
            }, 0, result, ['address1']);
            should.exist(result.addresses);
            result.addresses['address1'].inputIndexes.should.deep.equal([0]);
            result.addresses['address1'].outputIndexes.should.deep.equal([]);
        });
        it('will push to inputIndexes', function () {
            const bitcoind = new Blockchain(baseConfig);
            const result = {
                addresses: {
                    address1: {
                        inputIndexes: [1]
                    }
                }
            };
            bitcoind._getAddressDetailsForInput({
                address: 'address1'
            }, 2, result, ['address1']);
            should.exist(result.addresses);
            result.addresses['address1'].inputIndexes.should.deep.equal([1, 2]);
        });
    });

    describe('#_getAddressDetailsForOutput', function () {
        it('will return if missing an address', function () {
            const bitcoind = new Blockchain(baseConfig);
            const result = {};
            bitcoind._getAddressDetailsForOutput({}, 0, result, []);
            should.not.exist(result.addresses);
            should.not.exist(result.satoshis);
        });
        it('will only add address if it matches', function () {
            const bitcoind = new Blockchain(baseConfig);
            const result = {};
            bitcoind._getAddressDetailsForOutput({
                address: 'address1'
            }, 0, result, ['address2']);
            should.not.exist(result.addresses);
            should.not.exist(result.satoshis);
        });
        it('will instantiate if outputIndexes not defined', function () {
            const bitcoind = new Blockchain(baseConfig);
            const result = {
                addresses: {}
            };
            bitcoind._getAddressDetailsForOutput({
                address: 'address1'
            }, 0, result, ['address1']);
            should.exist(result.addresses);
            result.addresses['address1'].inputIndexes.should.deep.equal([]);
            result.addresses['address1'].outputIndexes.should.deep.equal([0]);
        });
        it('will push if outputIndexes defined', function () {
            const bitcoind = new Blockchain(baseConfig);
            const result = {
                addresses: {
                    address1: {
                        outputIndexes: [0]
                    }
                }
            };
            bitcoind._getAddressDetailsForOutput({
                address: 'address1'
            }, 1, result, ['address1']);
            should.exist(result.addresses);
            result.addresses['address1'].outputIndexes.should.deep.equal([0, 1]);
        });
    });

    describe('#_getAddressDetailsForTransaction', function () {
        it('will calculate details for the transaction', function () {
            /* jshint sub:true */
            const tx = {
                inputs: [
                    {
                        satoshis: 1000000000,
                        address: 'mgY65WSfEmsyYaYPQaXhmXMeBhwp4EcsQW'
                    }
                ],
                outputs: [
                    {
                        satoshis: 100000000,
                        address: 'mgY65WSfEmsyYaYPQaXhmXMeBhwp4EcsQW'
                    },
                    {
                        satoshis: 200000000,
                        address: 'mgY65WSfEmsyYaYPQaXhmXMeBhwp4EcsQW'
                    },
                    {
                        satoshis: 50000000,
                        address: 'mgY65WSfEmsyYaYPQaXhmXMeBhwp4EcsQW'
                    },
                    {
                        satoshis: 300000000,
                        address: 'mgY65WSfEmsyYaYPQaXhmXMeBhwp4EcsQW'
                    },
                    {
                        satoshis: 349990000,
                        address: 'mgY65WSfEmsyYaYPQaXhmXMeBhwp4EcsQW'
                    }
                ],
                locktime: 0
            };
            const bitcoind = new Blockchain(baseConfig);
            const addresses = ['mgY65WSfEmsyYaYPQaXhmXMeBhwp4EcsQW'];
            const details = bitcoind._getAddressDetailsForTransaction(tx, addresses);
            should.exist(details.addresses['mgY65WSfEmsyYaYPQaXhmXMeBhwp4EcsQW']);
            details.addresses['mgY65WSfEmsyYaYPQaXhmXMeBhwp4EcsQW'].inputIndexes.should.deep.equal([0]);
            details.addresses['mgY65WSfEmsyYaYPQaXhmXMeBhwp4EcsQW'].outputIndexes.should.deep.equal([
                0, 1, 2, 3, 4
            ]);
            details.satoshis.should.equal(-10000);
        });
    });

    describe('#_getAddressDetailedTransaction', function () {
        it('will get detailed transaction info', async function () {
            const txid = '46f24e0c274fc07708b781963576c4c5d5625d926dbb0a17fa865dcd9fe58ea0';
            const tx = {
                height: 20,
            };
            const bitcoind = new Blockchain(baseConfig);
            bitcoind.getDetailedTransaction = sinon.stub().resolves(tx);
            bitcoind.height = 300;
            const addresses = {};
            bitcoind._getAddressDetailsForTransaction = sinon.stub().returns({
                addresses: addresses,
                satoshis: 1000,
            });
            let err;
            let details;
            try {
                details = await bitcoind._getAddressDetailedTransaction(txid, {});
            } catch (e) {
                err = e;
            }
            should.not.exist(err);

            details.addresses.should.equal(addresses);
            details.satoshis.should.equal(1000);
            details.confirmations.should.equal(281);
            details.tx.should.equal(tx);

        });
        it('give error from getDetailedTransaction', async function () {
            const txid = '46f24e0c274fc07708b781963576c4c5d5625d926dbb0a17fa865dcd9fe58ea0';
            const bitcoind = new Blockchain(baseConfig);
            bitcoind.getDetailedTransaction = sinon.stub().rejects(new Error('test'));
            let err;
            try {
                await bitcoind._getAddressDetailedTransaction(txid, {});
            } catch (e) {
                err = e;
            }
            err.should.be.instanceof(Error);
        });
    });

    describe('#_getAddressStrings', function () {
        it('will get address strings from btc addresses', function () {
            const addresses = [
                btcLib.Address('1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i'),
                btcLib.Address('3CMNFxN1oHBc4R1EpboAL5yzHGgE611Xou'),
            ];
            const bitcoind = new Blockchain(baseConfig);
            const strings = bitcoind._getAddressStrings(addresses);
            strings[0].should.equal('1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i');
            strings[1].should.equal('3CMNFxN1oHBc4R1EpboAL5yzHGgE611Xou');
        });
        it('will get address strings from strings', function () {
            const addresses = [
                '1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i',
                '3CMNFxN1oHBc4R1EpboAL5yzHGgE611Xou',
            ];
            const bitcoind = new Blockchain(baseConfig);
            const strings = bitcoind._getAddressStrings(addresses);
            strings[0].should.equal('1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i');
            strings[1].should.equal('3CMNFxN1oHBc4R1EpboAL5yzHGgE611Xou');
        });
        it('will get address strings from mixture of types', function () {
            const addresses = [
                btcLib.Address('1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i'),
                '3CMNFxN1oHBc4R1EpboAL5yzHGgE611Xou',
            ];
            const bitcoind = new Blockchain(baseConfig);
            const strings = bitcoind._getAddressStrings(addresses);
            strings[0].should.equal('1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i');
            strings[1].should.equal('3CMNFxN1oHBc4R1EpboAL5yzHGgE611Xou');
        });
        it('will give error with unknown', function () {
            const addresses = [
                btcLib.Address('1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i'),
                0,
            ];
            const bitcoind = new Blockchain(baseConfig);
            (function () {
                bitcoind._getAddressStrings(addresses);
            }).should.throw(TypeError);
        });
    });

    describe('#_paginateTxids', function () {
        it('slice txids based on "from" and "to" (3 to 13)', function () {
            const bitcoind = new Blockchain(baseConfig);
            const txids = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
            const paginated = bitcoind._paginateTxids(txids, 3, 13);
            paginated.should.deep.equal([3, 4, 5, 6, 7, 8, 9, 10]);
        });
        it('slice txids based on "from" and "to" (0 to 3)', function () {
            const bitcoind = new Blockchain(baseConfig);
            const txids = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
            const paginated = bitcoind._paginateTxids(txids, 0, 3);
            paginated.should.deep.equal([0, 1, 2]);
        });
        it('slice txids based on "from" and "to" (0 to 1)', function () {
            const bitcoind = new Blockchain(baseConfig);
            const txids = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
            const paginated = bitcoind._paginateTxids(txids, 0, 1);
            paginated.should.deep.equal([0]);
        });
        it('will throw error if "from" is greater than "to"', function () {
            const bitcoind = new Blockchain(baseConfig);
            const txids = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
            (function () {
                bitcoind._paginateTxids(txids, 1, 0);
            }).should.throw('"from" (1) is expected to be less than "to"');
        });
        it('will handle string numbers', function () {
            const bitcoind = new Blockchain(baseConfig);
            const txids = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
            const paginated = bitcoind._paginateTxids(txids, '1', '3');
            paginated.should.deep.equal([1, 2]);
        });
    });

    describe('#getAddressHistory', function () {
        const address = '12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX';
        it('will give error with "from" and "to" range that exceeds max size', async function () {
            const bitcoind = new Blockchain(baseConfig);
            let err;
            try {
                await bitcoind.getAddressHistory(address, {from: 0, to: 51});
            } catch (e) {
                err = e;
            }
            should.exist(err);
            err.message.match(/^"from/);
        });
        it('will give error with "from" and "to" order is reversed', async function () {
            const bitcoind = new Blockchain(baseConfig);
            bitcoind.getAddressTxids = sinon.stub().resolves([]);
            let err;
            try {
                await bitcoind.getAddressHistory(address, {from: 51, to: 0});
            } catch (e) {
                err = e;
            }
            should.exist(err);
            err.message.match(/^"from/);
        });
        it('will give error from _getAddressDetailedTransaction', async function () {
            const bitcoind = new Blockchain(baseConfig);
            bitcoind.getAddressTxids = sinon.stub().resolves(['txid']);
            bitcoind._getAddressDetailedTransaction = sinon.stub().rejects(new Error('test'));
            let err;
            try {
                await bitcoind.getAddressHistory(address, {});
            } catch (e) {
                err = e;
            }

            should.exist(err);
            err.message.should.equal('test');
        });
        it('will give an error if length of addresses is too long', async function () {
            const addresses = [];
            for (let i = 0; i < 101; i++) {
                addresses.push(address);
            }
            const bitcoind = new Blockchain(baseConfig);
            bitcoind.maxAddressesQuery = 100;
            let err;
            try {
                await bitcoind.getAddressHistory(address, {});
            } catch (e) {
                err = e;
            }                should.exist(err);
            err.message.match(/Maximum/);
        });
        it('give error from getAddressTxids', async function () {
            const bitcoind = new Blockchain(baseConfig);
            bitcoind.getAddressTxids = sinon.stub().rejects(new Error('test'));
            let err;
            try {
                await bitcoind.getAddressHistory(address, {});
            } catch (e) {
                err = e;
            }
            should.exist(err);
            err.should.be.instanceof(Error);
            err.message.should.equal('test');
        });
        it('will paginate', async function () {
            const bitcoind = new Blockchain(baseConfig);
            bitcoind._getAddressDetailedTransaction = async function (txid) {
                return txid;
            };
            const txids = ['one', 'two', 'three', 'four'];
            bitcoind.getAddressTxids = sinon.stub().resolves(txids);
            let err;
            let data;
            try {
                data = await bitcoind.getAddressHistory('address', {from: 1, to: 3});
            } catch (e) {
                err = e;
            }
            should.not.exist(err);
            data.items.length.should.equal(2);
            data.items.should.deep.equal(['two', 'three']);

        });
    });

    describe('#getAddressSummary', function () {
        const txid1 = '70d9d441d7409aace8e0ffe24ff0190407b2fcb405799a266e0327017288d1f8';
        const txid2 = '35fafaf572341798b2ce2858755afa7c8800bb6b1e885d3e030b81255b5e172d';
        const txid3 = '57b7842afc97a2b46575b490839df46e9273524c6ea59ba62e1e86477cf25247';
        const memtxid1 = 'b1bfa8dbbde790cb46b9763ef3407c1a21c8264b67bfe224f462ec0e1f569e92';
        const memtxid2 = 'e9dcf22807db77ac0276b03cc2d3a8b03c4837db8ac6650501ef45af1c807cce';
        it('will handle error from getAddressTxids', async function () {
            const bitcoind = new Blockchain(baseConfig);
            bitcoind.nodes.push({
                client: {
                    getAddressMempool: sinon.stub().resolves([
                        {
                            txid: '70d9d441d7409aace8e0ffe24ff0190407b2fcb405799a266e0327017288d1f8',
                        }
                    ])
                }
            });
            bitcoind.getAddressTxids = sinon.stub().rejects(new Error('test'));
            bitcoind.getAddressBalance = sinon.stub().resolves({});
            const address = '';
            const options = {};
            let err;
            try {
                await bitcoind.getAddressSummary(address, options);
            } catch (e) {
                err = e;
            }
            should.exist(err);
            err.should.be.instanceof(Error);
            err.message.should.equal('test');
        });
        it('will handle error from getAddressBalance', async function () {
            const bitcoind = new Blockchain(baseConfig);
            bitcoind.nodes.push({
                client: {
                    getAddressMempool: sinon.stub().resolves([
                        {
                            txid: '70d9d441d7409aace8e0ffe24ff0190407b2fcb405799a266e0327017288d1f8',
                        }
                    ])
                }
            });
            bitcoind.getAddressTxids = sinon.stub().resolves({});
            bitcoind.getAddressBalance = sinon.stub().rejects(new Error('test'), {});
            const address = '';
            const options = {};
            let err;
            try {
                await bitcoind.getAddressSummary(address, options);
            } catch (e) {
                err = e;
            }
            should.exist(err);
            err.should.be.instanceof(Error);
            err.message.should.equal('test');
        });
        it('will handle error from client getAddressMempool', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const rpcError = new RPCError('Test error');
            rpcError.code = -1;
            bitcoind.nodes.push({
                client: {
                    getAddressMempool: sinon.stub().rejects(rpcError)
                }
            });
            bitcoind.getAddressTxids = sinon.stub().resolves({});
            bitcoind.getAddressBalance = sinon.stub().resolves({});
            const address = '';
            const options = {};
            let err;
            try {
                await bitcoind.getAddressSummary(address, options);
            } catch (e) {
                err = e;
            }
            should.exist(err);
            err.should.be.instanceof(Error);
            err.message.should.equal('Test error');

        });
        it('should set all properties', async function () {
            const bitcoind = new Blockchain(baseConfig);
            bitcoind.nodes.push({
                client: {
                    getAddressMempool: sinon.stub().resolves([
                        {
                            txid: memtxid1,
                            satoshis: -1000000
                        },
                        {
                            txid: memtxid2,
                            satoshis: 99999
                        }
                    ])
                }
            });
            sinon.spy(bitcoind, '_paginateTxids');
            bitcoind.getAddressTxids = sinon.stub().resolves([txid1, txid2, txid3]);
            bitcoind.getAddressBalance = sinon.stub().resolves({
                received: 30 * 1e8,
                balance: 20 * 1e8
            });
            const address = '3NbU8XzUgKyuCgYgZEKsBtUvkTm2r7Xgwj';
            const options = {};
            let err;
            let summary;
            try {
                summary = await bitcoind.getAddressSummary(address, options);
            } catch (e) {
                err = e;
            }
            should.not.exist(err);
            bitcoind._paginateTxids.callCount.should.equal(1);
            bitcoind._paginateTxids.args[0][1].should.equal(0);
            bitcoind._paginateTxids.args[0][2].should.equal(1000);
            summary.appearances.should.equal(3);
            summary.totalReceived.should.equal(3000000000);
            summary.totalSpent.should.equal(1000000000);
            summary.balance.should.equal(2000000000);
            summary.unconfirmedAppearances.should.equal(2);
            summary.unconfirmedBalance.should.equal(-900001);
            summary.txids.should.deep.equal([
                'e9dcf22807db77ac0276b03cc2d3a8b03c4837db8ac6650501ef45af1c807cce',
                'b1bfa8dbbde790cb46b9763ef3407c1a21c8264b67bfe224f462ec0e1f569e92',
                '70d9d441d7409aace8e0ffe24ff0190407b2fcb405799a266e0327017288d1f8',
                '35fafaf572341798b2ce2858755afa7c8800bb6b1e885d3e030b81255b5e172d',
                '57b7842afc97a2b46575b490839df46e9273524c6ea59ba62e1e86477cf25247'
            ]);
        });
        it('will give error with "from" and "to" range that exceeds max size', async function () {
            const bitcoind = new Blockchain(baseConfig);
            bitcoind.nodes.push({
                client: {
                    getAddressMempool: sinon.stub().resolves([
                        {
                            txid: memtxid1,
                            satoshis: -1000000
                        },
                        {
                            txid: memtxid2,
                            satoshis: 99999
                        }
                    ])
                }
            });
            bitcoind.getAddressTxids = sinon.stub().resolves([txid1, txid2, txid3]);
            bitcoind.getAddressBalance = sinon.stub().resolves({
                received: 30 * 1e8,
                balance: 20 * 1e8
            });
            const address = '3NbU8XzUgKyuCgYgZEKsBtUvkTm2r7Xgwj';
            const options = {
                from: 0,
                to: 1001
            };

            let err;
            try {
                await bitcoind.getAddressSummary(address, options);
            } catch (e) {
                err = e;
            }
            should.exist(err);
            err.message.match(/^"from/);
        });
        it('will get from cache with noTxList', async function () {
            const bitcoind = new Blockchain(baseConfig);
            bitcoind.nodes.push({
                client: {
                    getAddressMempool: sinon.stub().resolves([
                        {
                            txid: memtxid1,
                            satoshis: -1000000
                        },
                        {
                            txid: memtxid2,
                            satoshis: 99999
                        }
                    ])
                }
            });
            bitcoind.getAddressTxids = sinon.stub().resolves([txid1, txid2, txid3]);
            bitcoind.getAddressBalance = sinon.stub().resolves({
                received: 30 * 1e8,
                balance: 20 * 1e8
            });
            const address = '3NbU8XzUgKyuCgYgZEKsBtUvkTm2r7Xgwj';
            const options = {
                noTxList: true
            };
            function checkSummary(summary) {
                summary.appearances.should.equal(3);
                summary.totalReceived.should.equal(3000000000);
                summary.totalSpent.should.equal(1000000000);
                summary.balance.should.equal(2000000000);
                summary.unconfirmedAppearances.should.equal(2);
                summary.unconfirmedBalance.should.equal(-900001);
                should.not.exist(summary.txids);
            }
            let err;
            let summary;
            try {
                summary = await bitcoind.getAddressSummary(address, options);
            } catch (e) {
                err = e;
            }
            should.not.exist(err);
            checkSummary(summary);
            bitcoind.getAddressTxids.callCount.should.equal(1);
            bitcoind.getAddressBalance.callCount.should.equal(1);
            let err2;
            let summary2;
            try {
                summary2 = await bitcoind.getAddressSummary(address, options);
            } catch (e) {
                err2 = e;
            }
            should.not.exist(err2);
            checkSummary(summary2);
            bitcoind.getAddressTxids.callCount.should.equal(1);
            bitcoind.getAddressBalance.callCount.should.equal(1);

        });
        it('will skip querying the mempool with queryMempool set to false', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const getAddressMempool = sinon.stub();
            bitcoind.nodes.push({
                client: {
                    getAddressMempool: getAddressMempool
                }
            });
            sinon.spy(bitcoind, '_paginateTxids');
            bitcoind.getAddressTxids = sinon.stub().resolves([txid1, txid2, txid3]);
            bitcoind.getAddressBalance = sinon.stub().resolves({
                received: 30 * 1e8,
                balance: 20 * 1e8
            });
            const address = '3NbU8XzUgKyuCgYgZEKsBtUvkTm2r7Xgwj';
            const options = {
                queryMempool: false
            };
            let err;
            try {
                await bitcoind.getAddressSummary(address, options);
            } catch (e) {
                err = e;
            }
            should.not.exist(err);
            getAddressMempool.callCount.should.equal(0);
        });
        it('will give error from _paginateTxids', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const getAddressMempool = sinon.stub();
            bitcoind.nodes.push({
                client: {
                    getAddressMempool: getAddressMempool
                }
            });
            sinon.spy(bitcoind, '_paginateTxids');
            bitcoind.getAddressTxids = sinon.stub().resolves([txid1, txid2, txid3]);
            bitcoind.getAddressBalance = sinon.stub().resolves({
                received: 30 * 1e8,
                balance: 20 * 1e8
            });
            bitcoind._paginateTxids = sinon.stub().throws(new Error('test'));
            const address = '3NbU8XzUgKyuCgYgZEKsBtUvkTm2r7Xgwj';
            const options = {
                queryMempool: false
            };
            let err;
            try {
                await bitcoind.getAddressSummary(address, options);
            } catch (e) {
                err = e;
            }
            err.should.be.instanceOf(Error);
            err.message.should.equal('test');

        });
    });

    describe('#getRawBlock', function () {
        const blockhash = '00000000050a6d07f583beba2d803296eb1e9d4980c4a20f206c584e89a4f02b';
        const blockhex = '0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000';
        it('will give rcp error from client getblockhash', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const rpcError = new RPCError('Test error');
            rpcError.code = -1;
            bitcoind.nodes.push({
                client: {
                    getBlockHash: sinon.stub().rejects(rpcError)
                }
            });
            let err;
            try {
                await bitcoind.getRawBlock(10);
            } catch (e) {
                err = e;
            }
            should.exist(err);
            err.should.be.instanceof(errors.RPCError);
        });
        it('will give rcp error from client getblock', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const rpcError = new RPCError('Test error');
            rpcError.code = -1;
            bitcoind.nodes.push({
                client: {
                    getBlock: sinon.stub().rejects(rpcError)
                }
            });
            let err;
            try {
                await bitcoind.getRawBlock(blockhash);
            } catch (e) {
                err = e;
            }
            should.exist(err);
            err.should.be.instanceof(errors.RPCError);

        });
        it('will try all nodes for getblock', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const rpcError = new RPCError('Test error');
            rpcError.code = -1;
            const getBlockWithError = sinon.stub().rejects(rpcError);
            bitcoind.tryAllInterval = 1;
            bitcoind.nodes.push({
                client: {
                    getBlock: getBlockWithError
                }
            });
            bitcoind.nodes.push({
                client: {
                    getBlock: getBlockWithError
                }
            });
            bitcoind.nodes.push({
                client: {
                    getBlock: sinon.stub().resolves(blockhex)
                }
            });
            let err;
            let buffer;
            try {
                buffer = await bitcoind.getRawBlock(blockhash);
            } catch (e) {
                err = e;
            }
            should.not.exist(err);
            buffer.should.be.instanceof(Buffer);
            getBlockWithError.callCount.should.equal(2);
        });
        it('will get block from cache', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const getBlock = sinon.stub().resolves(blockhex);
            bitcoind.nodes.push({
                client: {
                    getBlock: getBlock
                }
            });
            let err;
            let buffer;
            try {
                buffer = await bitcoind.getRawBlock(blockhash);
            } catch (e) {
                err = e;
            }
            should.not.exist(err);
            buffer.should.be.instanceof(Buffer);
            getBlock.callCount.should.equal(1);
            try {
                buffer = await bitcoind.getRawBlock(blockhash);
            } catch (e) {
                err = e;
            }
            should.not.exist(err);
            buffer.should.be.instanceof(Buffer);
            getBlock.callCount.should.equal(1);

        });
        it('will get block by height', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const getBlock = sinon.stub().resolves(blockhex);
            const getBlockHash = sinon.stub().resolves('000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f');
            bitcoind.nodes.push({
                client: {
                    getBlock: getBlock,
                    getBlockHash: getBlockHash
                }
            });
            let err;
            let buffer;
            try {
                buffer = await bitcoind.getRawBlock(0);
            } catch (e) {
                err = e;
            }
            should.not.exist(err);
            buffer.should.be.instanceof(Buffer);
            getBlock.callCount.should.equal(1);
            getBlockHash.callCount.should.equal(1);

        });
    });

    describe('#getBlock', function () {
        const blockhex = '0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000';
        it('will give an rpc error from client getblock', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const getBlock = sinon.stub().callsArgWith(2, {code: -1, message: 'Test error'});
            const getBlockHash = sinon.stub().callsArgWith(1, null, {});
            bitcoind.nodes.push({
                client: {
                    getBlock: getBlock,
                    getBlockHash: getBlockHash
                }
            });
            let err;
            try {
                await bitcoind.getBlock(0);
            } catch (e) {
                err = e;
            }
            err.should.be.instanceof(Error);
        });
        it('will give an rpc error from client getblockhash', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const rpcError = new RPCError('Test error');
            rpcError.code = -1;
            const getBlockHash = sinon.stub().rejects(rpcError);
            bitcoind.nodes.push({
                client: {
                    getBlockHash: getBlockHash
                }
            });
            let err;
            try {
                await bitcoind.getBlock(0);
            } catch (e) {
                err = e;
            }
            err.should.be.instanceof(Error);
        });
        it('will getblock as btc object from height', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const getBlock = sinon.stub().resolves(blockhex);
            const getBlockHash = sinon.stub().resolves('00000000050a6d07f583beba2d803296eb1e9d4980c4a20f206c584e89a4f02b');
            bitcoind.nodes.push({
                client: {
                    getBlock: getBlock,
                    getBlockHash: getBlockHash
                }
            });
            let err;
            let block;
            try {
                block = await bitcoind.getBlock(0);
            } catch (e) {
                err = e;
            }

            should.not.exist(err);
            getBlock.args[0][0].should.equal('00000000050a6d07f583beba2d803296eb1e9d4980c4a20f206c584e89a4f02b');
            getBlock.args[0][1].should.equal(false);
            block.should.be.instanceof(btcLib.Block);
        });
        it('will getblock as btc object', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const getBlock = sinon.stub().resolves(blockhex);
            const getBlockHash = sinon.stub();
            bitcoind.nodes.push({
                client: {
                    getBlock: getBlock,
                    getBlockHash: getBlockHash
                }
            });
            let err;
            let block;
            try {
                block = await bitcoind.getBlock('00000000050a6d07f583beba2d803296eb1e9d4980c4a20f206c584e89a4f02b');
            } catch (e) {
                err = e;
            }
            should.not.exist(err);
            getBlockHash.callCount.should.equal(0);
            getBlock.callCount.should.equal(1);
            getBlock.args[0][0].should.equal('00000000050a6d07f583beba2d803296eb1e9d4980c4a20f206c584e89a4f02b');
            getBlock.args[0][1].should.equal(false);
            block.should.be.instanceof(btcLib.Block);
        });
        it('will get block from cache', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const getBlock = sinon.stub().resolves(blockhex);
            const getBlockHash = sinon.stub();
            bitcoind.nodes.push({
                client: {
                    getBlock: getBlock,
                    getBlockHash: getBlockHash
                }
            });
            const hash = '00000000050a6d07f583beba2d803296eb1e9d4980c4a20f206c584e89a4f02b';
            let err;
            let block;
            try {
                block = await bitcoind.getBlock(hash);
            } catch (e) {
                err = e;
            }
            should.not.exist(err);
            getBlockHash.callCount.should.equal(0);
            getBlock.callCount.should.equal(1);
            block.should.be.instanceof(btcLib.Block);
            try {
                block = await bitcoind.getBlock(hash);
            } catch (e) {
                err = e;
            }
            should.not.exist(err);
            getBlockHash.callCount.should.equal(0);
            getBlock.callCount.should.equal(1);
            block.should.be.instanceof(btcLib.Block);
        });
        it('will get block from cache with height (but not height)', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const getBlock = sinon.stub().resolves(blockhex);
            const getBlockHash = sinon.stub().resolves('00000000050a6d07f583beba2d803296eb1e9d4980c4a20f206c584e89a4f02b');
            bitcoind.nodes.push({
                client: {
                    getBlock: getBlock,
                    getBlockHash: getBlockHash
                }
            });
            let err;
            let block;
            try {
                block = await bitcoind.getBlock(0);
            } catch (e) {
                err = e;
            }
            should.not.exist(err);
            getBlockHash.callCount.should.equal(1);
            getBlock.callCount.should.equal(1);
            block.should.be.instanceof(btcLib.Block);
            try {
                block = await bitcoind.getBlock(0);
            } catch (e) {
                err = e;
            }
            should.not.exist(err);
            getBlockHash.callCount.should.equal(2);
            getBlock.callCount.should.equal(1);
            block.should.be.instanceof(btcLib.Block);
        });
    });

    describe('#getBlockHashesByTimestamp', function () {
        it('should give an rpc error', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const rpcError = new RPCError('error');
            rpcError.code = -1;
            const getBlockHashes = sinon.stub().rejects(rpcError);
            bitcoind.nodes.push({
                client: {
                    getBlockHashes: getBlockHashes
                }
            });
            let err;
            try {
                await bitcoind.getBlockHashesByTimestamp(1441911000, 1441914000);
            } catch (e) {
                err = e;
            }
            should.exist(err);
            err.message.should.equal('error');
        });
        it('should get the correct block hashes', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const block1 = '00000000050a6d07f583beba2d803296eb1e9d4980c4a20f206c584e89a4f02b';
            const block2 = '000000000383752a55a0b2891ce018fd0fdc0b6352502772b034ec282b4a1bf6';
            const getBlockHashes = sinon.stub().resolves([block2, block1]);
            bitcoind.nodes.push({
                client: {
                    getBlockHashes: getBlockHashes
                }
            });
            let err;
            let hashes;
            try {
                hashes = await bitcoind.getBlockHashesByTimestamp(1441914000, 1441911000);
            } catch (e) {
                err = e;
            }
            should.not.exist(err);
            hashes.should.deep.equal([block2, block1]);
        });
    });

    describe('#getBlockHeader', function () {
        const blockhash = '00000000050a6d07f583beba2d803296eb1e9d4980c4a20f206c584e89a4f02b';
        it('will give error from getBlockHash', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const rpcError = new RPCError('Test error');
            rpcError.code = -1;
            const getBlockHash = sinon.stub().rejects(rpcError);
            bitcoind.nodes.push({
                client: {
                    getBlockHash: getBlockHash
                }
            });
            let err;
            try {
                await bitcoind.getBlockHeader(10);
            } catch (e) {
                err = e;
            }
            err.should.be.instanceof(Error);
        });
        it('it will give rpc error from client getblockheader', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const rpcError = new RPCError('Test error');
            rpcError.code = -1;
            const getBlockHeader = sinon.stub().rejects(rpcError);
            bitcoind.nodes.push({
                client: {
                    getBlockHeader: getBlockHeader
                }
            });
            let err;
            try {
                await bitcoind.getBlockHeader(blockhash);
            } catch (e) {
                err = e;
            }
            err.should.be.instanceof(Error);
        });
        it('it will give rpc error from client getblockhash', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const getBlockHeader = sinon.stub();
            const rpcError = new RPCError('Test error');
            rpcError.code = -1;
            const getBlockHash = sinon.stub().rejects(rpcError);
            bitcoind.nodes.push({
                client: {
                    getBlockHeader: getBlockHeader,
                    getBlockHash: getBlockHash
                }
            });
            let err;
            try {
                await bitcoind.getBlockHeader(0);
            } catch (e) {
                err = e;
            }
            err.should.be.instanceof(Error);
        });
        it('will give result from client getblockheader (from height)', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const result = {
                hash: '0000000000000a817cd3a74aec2f2246b59eb2cbb1ad730213e6c4a1d68ec2f6',
                version: 536870912,
                confirmations: 5,
                height: 828781,
                chainWork: '00000000000000000000000000000000000000000000000ad467352c93bc6a3b',
                prevHash: '0000000000000504235b2aff578a48470dbf6b94dafa9b3703bbf0ed554c9dd9',
                nextHash: '00000000000000eedd967ec155f237f033686f0924d574b946caf1b0e89551b8',
                merkleRoot: '124e0f3fb5aa268f102b0447002dd9700988fc570efcb3e0b5b396ac7db437a9',
                time: 1462979126,
                medianTime: 1462976771,
                nonce: 2981820714,
                bits: '1a13ca10',
                difficulty: 847779.0710240941
            };
            const getBlockHeader = sinon.stub().resolves({
                hash: '0000000000000a817cd3a74aec2f2246b59eb2cbb1ad730213e6c4a1d68ec2f6',
                version: 536870912,
                confirmations: 5,
                height: 828781,
                chainwork: '00000000000000000000000000000000000000000000000ad467352c93bc6a3b',
                previousblockhash: '0000000000000504235b2aff578a48470dbf6b94dafa9b3703bbf0ed554c9dd9',
                nextblockhash: '00000000000000eedd967ec155f237f033686f0924d574b946caf1b0e89551b8',
                merkleroot: '124e0f3fb5aa268f102b0447002dd9700988fc570efcb3e0b5b396ac7db437a9',
                time: 1462979126,
                mediantime: 1462976771,
                nonce: 2981820714,
                bits: '1a13ca10',
                difficulty: 847779.0710240941

            });
            const getBlockHash = sinon.stub().resolves(blockhash
            );
            bitcoind.nodes.push({
                client: {
                    getBlockHeader: getBlockHeader,
                    getBlockHash: getBlockHash
                }
            });
            let err;
            let blockHeader;
            try {
                blockHeader = await bitcoind.getBlockHeader(0);
            } catch (e) {
                err = e;
            }
            should.not.exist(err);
            getBlockHeader.args[0][0].should.equal(blockhash);
            blockHeader.should.deep.equal(result);
        });
        it('will give result from client getblockheader (from hash)', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const result = {
                hash: '0000000000000a817cd3a74aec2f2246b59eb2cbb1ad730213e6c4a1d68ec2f6',
                version: 536870912,
                confirmations: 5,
                height: 828781,
                chainWork: '00000000000000000000000000000000000000000000000ad467352c93bc6a3b',
                prevHash: '0000000000000504235b2aff578a48470dbf6b94dafa9b3703bbf0ed554c9dd9',
                nextHash: '00000000000000eedd967ec155f237f033686f0924d574b946caf1b0e89551b8',
                merkleRoot: '124e0f3fb5aa268f102b0447002dd9700988fc570efcb3e0b5b396ac7db437a9',
                time: 1462979126,
                medianTime: 1462976771,
                nonce: 2981820714,
                bits: '1a13ca10',
                difficulty: 847779.0710240941
            };
            const getBlockHeader = sinon.stub().resolves({
                hash: '0000000000000a817cd3a74aec2f2246b59eb2cbb1ad730213e6c4a1d68ec2f6',
                version: 536870912,
                confirmations: 5,
                height: 828781,
                chainwork: '00000000000000000000000000000000000000000000000ad467352c93bc6a3b',
                previousblockhash: '0000000000000504235b2aff578a48470dbf6b94dafa9b3703bbf0ed554c9dd9',
                nextblockhash: '00000000000000eedd967ec155f237f033686f0924d574b946caf1b0e89551b8',
                merkleroot: '124e0f3fb5aa268f102b0447002dd9700988fc570efcb3e0b5b396ac7db437a9',
                time: 1462979126,
                mediantime: 1462976771,
                nonce: 2981820714,
                bits: '1a13ca10',
                difficulty: 847779.0710240941
            });
            const getBlockHash = sinon.stub();
            bitcoind.nodes.push({
                client: {
                    getBlockHeader: getBlockHeader,
                    getBlockHash: getBlockHash
                }
            });
            let err;
            let blockHeader;
            try {
                blockHeader = await bitcoind.getBlockHeader(blockhash);
            } catch (e) {
                err = e;
            }
            should.not.exist(err);
            getBlockHash.callCount.should.equal(0);
            blockHeader.should.deep.equal(result);
        });
    });

    describe('#_maybeGetBlockHash', function () {
        it('will not get block hash with an address', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const getBlockHash = sinon.stub();
            bitcoind.nodes.push({
                client: {
                    getBlockHash: getBlockHash
                }
            });
            let err;
            let hash;
            try {
                hash = await bitcoind._maybeGetBlockHash('2N2JD6wb56AfK4tfmM6PwdVmoYk2dCKf4Br');
            } catch (e) {
                err = e;
            }
            should.not.exist(err);
            getBlockHash.callCount.should.equal(0);
            hash.should.equal('2N2JD6wb56AfK4tfmM6PwdVmoYk2dCKf4Br');
        });
        it('will not get block hash with non zero-nine numeric string', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const getBlockHash = sinon.stub();
            bitcoind.nodes.push({
                client: {
                    getBlockHash: getBlockHash
                }
            });
            let err;
            let hash;
            try {
                hash = await bitcoind._maybeGetBlockHash('109a');
            } catch (e) {
                err = e;
            }
            should.not.exist(err);
            getBlockHash.callCount.should.equal(0);
            hash.should.equal('109a');
        });
        it('will get the block hash if argument is a number', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const getBlockHash = sinon.stub().resolves('blockhash');
            bitcoind.nodes.push({
                client: {
                    getBlockHash: getBlockHash
                }
            });
            let err;
            let hash;
            try {
                hash = await bitcoind._maybeGetBlockHash(10);
            } catch (e) {
                err = e;
            }
            should.not.exist(err);
            hash.should.equal('blockhash');
            getBlockHash.callCount.should.equal(1);
        });
        it('will get the block hash if argument is a number (as string)', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const getBlockHash = sinon.stub().resolves('blockhash');
            bitcoind.nodes.push({
                client: {
                    getBlockHash: getBlockHash
                }
            });
            let err;
            let hash;
            try {
                hash = await bitcoind._maybeGetBlockHash('10');
            } catch (e) {
                err = e;
            }
            should.not.exist(err);
            hash.should.equal('blockhash');
            getBlockHash.callCount.should.equal(1);
        });
        it('will try multiple nodes if one fails', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const getBlockHash = sinon.stub().resolves('blockhash');
            const rpcError = new RPCError('test');
            rpcError.code = -1;
            getBlockHash.onCall(0).rejects(rpcError);
            bitcoind.tryAllInterval = 1;
            bitcoind.nodes.push({
                client: {
                    getBlockHash: getBlockHash
                }
            });
            bitcoind.nodes.push({
                client: {
                    getBlockHash: getBlockHash
                }
            });
            let err;
            let hash;
            try {
                hash = await bitcoind._maybeGetBlockHash(10);
            } catch (e) {
                err = e;
            }
            should.not.exist(err);
            hash.should.equal('blockhash');
            getBlockHash.callCount.should.equal(2);
        });
        it('will give error from getBlockHash', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const rpcError = new RPCError('test');
            rpcError.code = -1;
            const getBlockHash = sinon.stub().rejects(rpcError);
            bitcoind.tryAllInterval = 1;
            bitcoind.nodes.push({
                client: {
                    getBlockHash: getBlockHash
                }
            });
            bitcoind.nodes.push({
                client: {
                    getBlockHash: getBlockHash
                }
            });
            let err;
            try {
                await bitcoind._maybeGetBlockHash(10);
            } catch (e) {
                err = e;
            }
            getBlockHash.callCount.should.equal(2);
            err.should.be.instanceOf(Error);
            err.message.should.equal('test');
            err.code.should.equal(-1);
        });
    });

    describe('#getBlockOverview', function () {
        const blockhash = '00000000050a6d07f583beba2d803296eb1e9d4980c4a20f206c584e89a4f02b';
        it('will handle error from maybeGetBlockHash', async function () {
            const bitcoind = new Blockchain(baseConfig);
            bitcoind._maybeGetBlockHash = sinon.stub().rejects( new Error('test'));
            let err;
            try {
                await bitcoind.getBlockOverview(blockhash);
            } catch (e) {
                err = e;
            }
            err.should.be.instanceOf(Error);
        });
        it('will give error from client.getBlock', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const rpcError = new RPCError('test');
            rpcError.code = -1;
            const getBlock = sinon.stub().rejects(rpcError);
            bitcoind.nodes.push({
                client: {
                    getBlock: getBlock
                }
            });
            let err;
            try {
                await bitcoind.getBlockOverview(blockhash);
            } catch (e) {
                err = e;
            }
            should.exist(err);
            err.should.be.instanceOf(Error);
            err.message.should.equal('test');
        });
        it('will give expected result', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const blockResult = {
                hash: blockhash,
                version: 536870912,
                confirmations: 5,
                height: 828781,
                chainwork: '00000000000000000000000000000000000000000000000ad467352c93bc6a3b',
                previousblockhash: '0000000000000504235b2aff578a48470dbf6b94dafa9b3703bbf0ed554c9dd9',
                nextblockhash: '00000000000000eedd967ec155f237f033686f0924d574b946caf1b0e89551b8',
                merkleroot: '124e0f3fb5aa268f102b0447002dd9700988fc570efcb3e0b5b396ac7db437a9',
                time: 1462979126,
                mediantime: 1462976771,
                nonce: 2981820714,
                bits: '1a13ca10',
                difficulty: 847779.0710240941
            };
            const getBlock = sinon.stub().resolves(blockResult);
            bitcoind.nodes.push({
                client: {
                    getBlock: getBlock
                }
            });
            function checkBlock(blockOverview) {
                blockOverview.hash.should.equal('00000000050a6d07f583beba2d803296eb1e9d4980c4a20f206c584e89a4f02b');
                blockOverview.version.should.equal(536870912);
                blockOverview.confirmations.should.equal(5);
                blockOverview.height.should.equal(828781);
                blockOverview.chainWork.should.equal('00000000000000000000000000000000000000000000000ad467352c93bc6a3b');
                blockOverview.prevHash.should.equal('0000000000000504235b2aff578a48470dbf6b94dafa9b3703bbf0ed554c9dd9');
                blockOverview.nextHash.should.equal('00000000000000eedd967ec155f237f033686f0924d574b946caf1b0e89551b8');
                blockOverview.merkleRoot.should.equal('124e0f3fb5aa268f102b0447002dd9700988fc570efcb3e0b5b396ac7db437a9');
                blockOverview.time.should.equal(1462979126);
                blockOverview.medianTime.should.equal(1462976771);
                blockOverview.nonce.should.equal(2981820714);
                blockOverview.bits.should.equal('1a13ca10');
                blockOverview.difficulty.should.equal(847779.0710240941);
            }
            let err;
            let blockOverview;
            try {
                blockOverview = await bitcoind.getBlockOverview(blockhash);
            } catch (e) {
                err = e;
            }
            should.not.exist(err);
            checkBlock(blockOverview);
            try {
                blockOverview = await bitcoind.getBlockOverview(blockhash);
            } catch (e) {
                err = e;
            }
            should.not.exist(err);
            checkBlock(blockOverview);
            getBlock.callCount.should.equal(1);
        });
    });

    describe('#estimateFee', function () {
        it('will give rpc error', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const rpcError = new RPCError('error');
            rpcError.code = -1;

            const estimateFee = sinon.stub().rejects(rpcError);
            bitcoind.nodes.push({
                client: {
                    estimateFee: estimateFee
                }
            });
            let err;
            try {
                await bitcoind.estimateFee(1);
            } catch (e) {
                err = e;
            }
            should.exist(err);
            err.should.be.an.instanceof(errors.RPCError);
        });
        it('will call client estimateFee and give result', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const estimateFee = sinon.stub().resolves(-1);
            bitcoind.nodes.push({
                client: {
                    estimateFee: estimateFee
                }
            });
            let err;
            let feesPerKb;
            try {
                feesPerKb = await bitcoind.estimateFee(1);
            } catch (e) {
                err = e;
            }
            should.not.exist(err);
            feesPerKb.should.equal(-1);
        });
    });

    describe('#sendTransaction', function () {
        const tx = btcLib.Transaction(txhex);
        it('will give rpc error', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const rpcError = new RPCError('error');
            rpcError.code = -1;
            const sendRawTransaction = sinon.stub().rejects(rpcError);
            bitcoind.nodes.push({
                client: {
                    sendRawTransaction: sendRawTransaction
                }
            });
            let err;
            try {
                await bitcoind.sendTransaction(txhex);
            } catch (e) {
                err = e;
            }
            should.exist(err);
            err.should.be.an.instanceof(errors.RPCError);
        });
        it('will send to client and get hash', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const sendRawTransaction = sinon.stub().resolves(tx.hash);
            bitcoind.nodes.push({
                client: {
                    sendRawTransaction: sendRawTransaction
                }
            });
            let err;
            let hash;
            try {
                hash = await bitcoind.sendTransaction(txhex);
            } catch (e) {
                err = e;
            }
            should.not.exist(err);
            hash.should.equal(tx.hash);
        });
        it('will send to client with absurd fees and get hash', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const sendRawTransaction = sinon.stub().resolves(tx.hash);
            bitcoind.nodes.push({
                client: {
                    sendRawTransaction: sendRawTransaction
                }
            });
            let err;
            let hash;
            try {
                hash = await bitcoind.sendTransaction(txhex, {allowAbsurdFees: true});
            } catch (e) {
                err = e;
            }
            should.not.exist(err);
            hash.should.equal(tx.hash);
        });
    });

    describe('#getRawTransaction', function () {
        it('will give rpc error', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const rpcError = new RPCError('error');
            rpcError.code = -1;
            const getRawTransaction = sinon.stub().rejects(rpcError);
            bitcoind.nodes.push({
                client: {
                    getRawTransaction: getRawTransaction
                }
            });
            let err;
            try {
                await bitcoind.getRawTransaction('txid');
            } catch (e) {
                err = e;
            }
            should.exist(err);
            err.should.be.an.instanceof(errors.RPCError);
        });
        it('will try all nodes', async function () {
            const bitcoind = new Blockchain(baseConfig);
            bitcoind.tryAllInterval = 1;
            const rpcError = new RPCError('error');
            rpcError.code = -1;
            const getRawTransactionWithError = sinon.stub().rejects(rpcError);
            const getRawTransaction = sinon.stub().resolves(txhex);
            bitcoind.nodes.push({
                client: {
                    getRawTransaction: getRawTransactionWithError
                }
            });
            bitcoind.nodes.push({
                client: {
                    getRawTransaction: getRawTransactionWithError
                }
            });
            bitcoind.nodes.push({
                client: {
                    getRawTransaction: getRawTransaction
                }
            });
            let err;
            let tx;
            try {
                tx = await bitcoind.getRawTransaction('txid');
            } catch (e) {
                err = e;
            }
            should.not.exist(err);
            should.exist(tx);
            tx.should.be.an.instanceof(Buffer);
        });
        it('will get from cache', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const getRawTransaction = sinon.stub().resolves(txhex);
            bitcoind.nodes.push({
                client: {
                    getRawTransaction: getRawTransaction
                }
            });
            let err;
            let tx;
            try {
                tx = await bitcoind.getRawTransaction('txid');
            } catch (e) {
                err = e;
            }
            should.not.exist(err);
            should.exist(tx);
            tx.should.be.an.instanceof(Buffer);

            try {
                tx = await bitcoind.getRawTransaction('txid');
            } catch (e) {
                err = e;
            }
            should.exist(tx);
            tx.should.be.an.instanceof(Buffer);
            getRawTransaction.callCount.should.equal(1);
        });
    });

    describe('#getTransaction', function () {
        it('will give rpc error', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const rpcError = new RPCError('error');
            rpcError.code = -1;
            const getRawTransaction = sinon.stub().rejects(rpcError);
            bitcoind.nodes.push({
                client: {
                    getRawTransaction: getRawTransaction
                }
            });
            let err;
            try {
                await bitcoind.getTransaction('txid');
            } catch (e) {
                err = e;
            }
            should.exist(err);
            err.should.be.an.instanceof(errors.RPCError);
        });
        it('will try all nodes', async function () {
            const bitcoind = new Blockchain(baseConfig);
            bitcoind.tryAllInterval = 1;
            const rpcError = new RPCError('error');
            rpcError.code = -1;
            const getRawTransactionWithError = sinon.stub().rejects(rpcError);
            const getRawTransaction = sinon.stub().resolves(txhex);
            bitcoind.nodes.push({
                client: {
                    getRawTransaction: getRawTransactionWithError
                }
            });
            bitcoind.nodes.push({
                client: {
                    getRawTransaction: getRawTransactionWithError
                }
            });
            bitcoind.nodes.push({
                client: {
                    getRawTransaction: getRawTransaction
                }
            });
            let err;
            let tx;
            try {
                tx = await bitcoind.getTransaction('txid');
            } catch (e) {
                err = e;
            }
            should.not.exist(err);
            should.exist(tx);
            tx.should.be.an.instanceof(btcLib.Transaction);

        });
        it('will get from cache', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const getRawTransaction = sinon.stub().resolves(txhex);
            bitcoind.nodes.push({
                client: {
                    getRawTransaction: getRawTransaction
                }
            });
            let err;
            let tx;
            try {
                tx = await bitcoind.getTransaction('txid');
            } catch (e) {
                err = e;
            }
            should.not.exist(err);
            should.exist(tx);
            tx.should.be.an.instanceof(btcLib.Transaction);

            try {
                tx = await bitcoind.getTransaction('txid');
            } catch (e) {
                err = e;
            }
            should.exist(tx);
            tx.should.be.an.instanceof(btcLib.Transaction);
            getRawTransaction.callCount.should.equal(1);

        });
    });

    describe('#getDetailedTransaction', function () {
        const txBuffer = Buffer.from('01000000016f95980911e01c2c664b3e78299527a47933aac61a515930a8fe0213d1ac9abe01000000da0047304402200e71cda1f71e087c018759ba3427eb968a9ea0b1decd24147f91544629b17b4f0220555ee111ed0fc0f751ffebf097bdf40da0154466eb044e72b6b3dcd5f06807fa01483045022100c86d6c8b417bff6cc3bbf4854c16bba0aaca957e8f73e19f37216e2b06bb7bf802205a37be2f57a83a1b5a8cc511dc61466c11e9ba053c363302e7b99674be6a49fc0147522102632178d046673c9729d828cfee388e121f497707f810c131e0d3fc0fe0bd66d62103a0951ec7d3a9da9de171617026442fcd30f34d66100fab539853b43f508787d452aeffffffff0240420f000000000017a9148a31d53a448c18996e81ce67811e5fb7da21e4468738c9d6f90000000017a9148ce5408cfeaddb7ccb2545ded41ef478109454848700000000', 'hex');
        const info = {
            blockHash: '00000000000ec715852ea2ecae4dc8563f62d603c820f81ac284cd5be0a944d6',
            height: 530482,
            timestamp: 1439559434000,
            buffer: txBuffer
        };
        const rpcRawTransaction = {
            hex: txBuffer.toString('hex'),
            blockhash: info.blockHash,
            height: info.height,
            version: 1,
            locktime: 411451,
            time: info.timestamp,
            vin: [
                {
                    valueSat: 110,
                    address: 'mgY65WSfEmsyYaYPQaXhmXMeBhwp4EcsQW',
                    txid: '3d003413c13eec3fa8ea1fe8bbff6f40718c66facffe2544d7516c9e2900cac2',
                    sequence: 0xFFFFFFFF,
                    vout: 0,
                    scriptSig: {
                        hex: 'scriptSigHex',
                        asm: 'scriptSigAsm'
                    }
                }
            ],
            vout: [
                {
                    spentTxId: '4316b98e7504073acd19308b4b8c9f4eeb5e811455c54c0ebfe276c0b1eb6315',
                    spentIndex: 2,
                    spentHeight: 100,
                    valueSat: 100,
                    scriptPubKey: {
                        hex: '76a9140b2f0a0c31bfe0406b0ccc1381fdbe311946dadc88ac',
                        asm: 'OP_DUP OP_HASH160 0b2f0a0c31bfe0406b0ccc1381fdbe311946dadc OP_EQUALVERIFY OP_CHECKSIG',
                        addresses: ['mgY65WSfEmsyYaYPQaXhmXMeBhwp4EcsQW']
                    }
                }
            ]
        };
        it('should give a transaction with height and timestamp', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const rpcError = new RPCError('Test error');
            rpcError.code = -1;
            bitcoind.nodes.push({
                client: {
                    getRawTransaction: sinon.stub().rejects(rpcError)
                }
            });
            const txid = '2d950d00494caf6bfc5fff2a3f839f0eb50f663ae85ce092bc5f9d45296ae91f';
            let err;
            try {
                await bitcoind.getDetailedTransaction(txid);
            } catch (e) {
                err = e;
            }
            should.exist(err);
            err.should.be.instanceof(errors.RPCError);
        });
        it('should give a transaction with all properties', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const getRawTransaction = sinon.stub().resolves(rpcRawTransaction);
            bitcoind.nodes.push({
                client: {
                    getRawTransaction: getRawTransaction
                }
            });
            const txid = '2d950d00494caf6bfc5fff2a3f839f0eb50f663ae85ce092bc5f9d45296ae91f';
            function checkTx(tx) {
                /* jshint maxstatements: 30 */
                should.exist(tx);
                should.not.exist(tx.coinbase);
                should.equal(tx.hex, txBuffer.toString('hex'));
                should.equal(tx.blockHash, '00000000000ec715852ea2ecae4dc8563f62d603c820f81ac284cd5be0a944d6');
                should.equal(tx.height, 530482);
                should.equal(tx.blockTimestamp, 1439559434000);
                should.equal(tx.version, 1);
                should.equal(tx.locktime, 411451);
                should.equal(tx.feeSatoshis, 10);
                should.equal(tx.inputSatoshis, 110);
                should.equal(tx.outputSatoshis, 100);
                should.equal(tx.hash, txid);
                const input = tx.inputs[0];
                should.equal(input.prevTxId, '3d003413c13eec3fa8ea1fe8bbff6f40718c66facffe2544d7516c9e2900cac2');
                should.equal(input.outputIndex, 0);
                should.equal(input.satoshis, 110);
                should.equal(input.sequence, 0xFFFFFFFF);
                should.equal(input.script, 'scriptSigHex');
                should.equal(input.scriptAsm, 'scriptSigAsm');
                should.equal(input.address, 'mgY65WSfEmsyYaYPQaXhmXMeBhwp4EcsQW');
                const output = tx.outputs[0];
                should.equal(output.satoshis, 100);
                should.equal(output.script, '76a9140b2f0a0c31bfe0406b0ccc1381fdbe311946dadc88ac');
                should.equal(output.scriptAsm, 'OP_DUP OP_HASH160 0b2f0a0c31bfe0406b0ccc1381fdbe311946dadc OP_EQUALVERIFY OP_CHECKSIG');
                should.equal(output.address, 'mgY65WSfEmsyYaYPQaXhmXMeBhwp4EcsQW');
                should.equal(output.spentTxId, '4316b98e7504073acd19308b4b8c9f4eeb5e811455c54c0ebfe276c0b1eb6315');
                should.equal(output.spentIndex, 2);
                should.equal(output.spentHeight, 100);
            }
            let err;
            let tx;
            try {
                tx = await bitcoind.getDetailedTransaction(txid);
            } catch (e) {
                err = e;
            }
            should.not.exist(err);
            checkTx(tx);
            try {
                tx = await bitcoind.getDetailedTransaction(txid);
            } catch (e) {
                err = e;
            }
            should.not.exist(err);
            checkTx(tx);
            getRawTransaction.callCount.should.equal(1);
        });
        it('should set coinbase to true', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const rawTransaction = JSON.parse((JSON.stringify(rpcRawTransaction)));
            delete rawTransaction.vin[0];
            rawTransaction.vin = [
                {
                    coinbase: 'abcdef'
                }
            ];
            bitcoind.nodes.push({
                client: {
                    getRawTransaction: sinon.stub().resolves(rawTransaction)
                }
            });
            const txid = '2d950d00494caf6bfc5fff2a3f839f0eb50f663ae85ce092bc5f9d45296ae91f';
            let err;
            let tx;
            try {
                tx = await bitcoind.getDetailedTransaction(txid);
            } catch (e) {
                err = e;
            }
            should.not.exist(err);
            should.exist(tx);
            should.equal(tx.coinbase, true);

        });
        it('will not include address if address length is zero', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const rawTransaction = JSON.parse((JSON.stringify(rpcRawTransaction)));
            rawTransaction.vout[0].scriptPubKey.addresses = [];
            bitcoind.nodes.push({
                client: {
                    getRawTransaction: sinon.stub().resolves(rawTransaction)
                }
            });
            const txid = '2d950d00494caf6bfc5fff2a3f839f0eb50f663ae85ce092bc5f9d45296ae91f';
            let err;
            let tx;
            try {
                tx = await bitcoind.getDetailedTransaction(txid);
            } catch (e) {
                err = e;
            }
            should.not.exist(err);
            should.exist(tx);
            should.equal(tx.outputs[0].address, null);
        });
        it('will not include address if address length is greater than 1', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const rawTransaction = JSON.parse((JSON.stringify(rpcRawTransaction)));
            rawTransaction.vout[0].scriptPubKey.addresses = ['one', 'two'];
            bitcoind.nodes.push({
                client: {
                    getRawTransaction: sinon.stub().resolves(rawTransaction)
                }
            });
            const txid = '2d950d00494caf6bfc5fff2a3f839f0eb50f663ae85ce092bc5f9d45296ae91f';
            let err;
            let tx;
            try {
                tx = await bitcoind.getDetailedTransaction(txid);
            } catch (e) {
                err = e;
            }
            should.not.exist(err);
            should.exist(tx);
            should.equal(tx.outputs[0].address, null);
        });
        it('will handle scriptPubKey.addresses not being set', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const rawTransaction = JSON.parse((JSON.stringify(rpcRawTransaction)));
            delete rawTransaction.vout[0].scriptPubKey['addresses'];
            bitcoind.nodes.push({
                client: {
                    getRawTransaction: sinon.stub().resolves( rawTransaction)
                }
            });
            const txid = '2d950d00494caf6bfc5fff2a3f839f0eb50f663ae85ce092bc5f9d45296ae91f';
            let err;
            let tx;
            try {
                tx = await bitcoind.getDetailedTransaction(txid);
            } catch (e) {
                err = e;
            }
            should.not.exist(err);
            should.exist(tx);
            should.equal(tx.outputs[0].address, null);
        });
        it('will not include script if input missing scriptSig or coinbase', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const rawTransaction = JSON.parse((JSON.stringify(rpcRawTransaction)));
            delete rawTransaction.vin[0].scriptSig;
            delete rawTransaction.vin[0].coinbase;
            bitcoind.nodes.push({
                client: {
                    getRawTransaction: sinon.stub().resolves(rawTransaction)
                }
            });
            const txid = '2d950d00494caf6bfc5fff2a3f839f0eb50f663ae85ce092bc5f9d45296ae91f';
            let err;
            let tx;
            try {
                tx = await bitcoind.getDetailedTransaction(txid);
            } catch (e) {
                err = e;
            }
            should.not.exist(err);
            should.exist(tx);
            should.equal(tx.inputs[0].script, null);
        });
        it('will set height to -1 if missing height', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const rawTransaction = JSON.parse((JSON.stringify(rpcRawTransaction)));
            delete rawTransaction.height;
            bitcoind.nodes.push({
                client: {
                    getRawTransaction: sinon.stub().resolves(rawTransaction)
                }
            });
            const txid = '2d950d00494caf6bfc5fff2a3f839f0eb50f663ae85ce092bc5f9d45296ae91f';
            let err;
            let tx;
            try {
                tx = await bitcoind.getDetailedTransaction(txid);
            } catch (e) {
                err = e;
            }
            should.not.exist(err);
            should.exist(tx);
            should.equal(tx.height, -1);
        });
    });

    describe('#getBestBlockHash', function () {
        it('will give rpc error', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const rpcError = new RPCError('error');
            rpcError.code = -1;
            const getBestBlockHash = sinon.stub().rejects(rpcError);
            bitcoind.nodes.push({
                client: {
                    getBestBlockHash: getBestBlockHash
                }
            });
            let err;
            try {
                await bitcoind.getBestBlockHash();
            } catch (e) {
                err = e;
            }
            should.exist(err);
            err.should.be.an.instanceof(errors.RPCError);
        });
        it('will call client getInfo and give result', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const getBestBlockHash = sinon.stub().resolves('besthash');
            bitcoind.nodes.push({
                client: {
                    getBestBlockHash: getBestBlockHash
                }
            });
            let err;
            let hash;
            try {
                hash = await bitcoind.getBestBlockHash();
            } catch (e) {
                err = e;
            }
            should.not.exist(err);
            should.exist(hash);
            hash.should.equal('besthash');
        });
    });

    describe('#getSpentInfo', function () {
        it('will give rpc error', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const rpcError = new RPCError('error');
            rpcError.code = -1;
            const getSpentInfo = sinon.stub().rejects(rpcError);
            bitcoind.nodes.push({
                client: {
                    getSpentInfo: getSpentInfo
                }
            });
            let err;
            try {
                await bitcoind.getSpentInfo({});
            } catch (e) {
                err = e;
            }
            should.exist(err);
            err.should.be.an.instanceof(errors.RPCError);
        });
        it('will empty object when not found', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const rpcError = new RPCError('test');
            rpcError.code = -5;
            const getSpentInfo = sinon.stub().rejects(rpcError);
            bitcoind.nodes.push({
                client: {
                    getSpentInfo: getSpentInfo
                }
            });
            let err;
            let info;
            try {
                info = await bitcoind.getSpentInfo({});
            } catch (e) {
                err = e;
            }
            should.not.exist(err);
            info.should.deep.equal({});
        });
        it('will call client getSpentInfo and give result', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const getSpentInfo = sinon.stub().resolves({
                txid: 'txid',
                index: 10,
                height: 101
            });
            bitcoind.nodes.push({
                client: {
                    getSpentInfo: getSpentInfo
                }
            });
            let err;
            let info;
            try {
                info = await bitcoind.getSpentInfo({});
            } catch (e) {
                err = e;
            }
            should.not.exist(err);
            info.txid.should.equal('txid');
            info.index.should.equal(10);
            info.height.should.equal(101);
        });
    });

    describe('#getInfo', function () {
        it('will give rpc error', async function () {
            const bitcoind = new Blockchain(baseConfig);
            const rpcError = new RPCError('error');
            rpcError.code = -5;
            const getInfo = sinon.stub().rejects(rpcError);
            bitcoind.nodes.push({
                client: {
                    getInfo: getInfo
                }
            });
            let err;
            try {
                await bitcoind.getInfo();
            } catch (e) {
                err = e;
            }
            should.exist(err);
            err.should.be.an.instanceof(errors.RPCError);
        });
        it('will call client getInfo and give result', async function () {
            const bitcoind = new Blockchain(baseConfig);
            bitcoind.node.getNetworkName = sinon.stub().returns('testnet');
            const getInfo = sinon.stub().resolves({
                version: 1,
                protocolversion: 1,
                blocks: 1,
                timeoffset: 1,
                connections: 1,
                proxy: '',
                difficulty: 1,
                testnet: true,
                relayfee: 10,
                errors: ''
            });
            const getNetworkInfo = sinon.stub().resolves({
                subversion: 1,
                localservices: 'services'
            });
            bitcoind.nodes.push({
                client: {
                    getInfo: getInfo,
                    getNetworkInfo: getNetworkInfo
                }
            });
            let err;
            let info;
            try {
                info = await bitcoind.getInfo();
            } catch (e) {
                err = e;
            }
            should.not.exist(err);
            should.exist(info);
            should.equal(info.version, 1);
            should.equal(info.protocolVersion, 1);
            should.equal(info.blocks, 1);
            should.equal(info.timeOffset, 1);
            should.equal(info.connections, 1);
            should.equal(info.proxy, '');
            should.equal(info.difficulty, 1);
            should.equal(info.testnet, true);
            should.equal(info.relayFee, 10);
            should.equal(info.errors, '');
            should.equal(info.subversion, 1);
            should.equal(info.localServices, 'services');
            info.network.should.equal('testnet');

        });
    });

    describe('#stop', function () {
        it('is an async stub', function () {
            const bitcoind = new Blockchain(baseConfig);
            return bitcoind.stop();
        });
    });
});
