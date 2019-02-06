# hapi-blockchain

[![NPM Package](https://img.shields.io/npm/v/@owstack/hapi-blockchain.svg?style=flat-square)](https://www.npmjs.org/package/@owstack/hapi-blockchain)
[![Build Status](https://img.shields.io/travis/com/owstack/hapi-blockchain.svg?branch=master&style=flat-square)](https://travis-ci.com/owstack/hapi-blockchain)
[![Coverage Status](https://img.shields.io/coveralls/owstack/hapi-blockchain.svg?style=flat-square)](https://coveralls.io/r/owstack/hapi-blockchain)


This is a Hapi.js plugin for connecting to a cluster of Bitcoin, Bitcoin Cash, or Litecoin services via RPC.

This plugin binds to the hapi server and emits events on incoming blocks, transactions, or address txids.

This plugin also provides an API of helper functions for working with blockchain data.

### configuration

This plugin expects a configuration object with the following properties. Supported currency options: 'BTC', 'BCH', or 'LTC'

```json
{
    "currency": "BTC",
    "nodes": [
        {
            "protocol": "http",
            "host": "127.0.0.1",
            "port": 12345,
            "user": "someUsername",
            "pass": "somePassword"
        }
    ]
}

```

If multiple nodes are provided, then round-robin load-balancing is used;

### credits

This code and tests were adapted from code in the bitcore-node package by BitPay.
