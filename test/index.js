'use strict';

const Hapi = require('hapi');
const Code = require('code');
const Lab = require('lab');

const HapiIpWhitelist = require('../lib/plugin.js');
const TestSchemes = require('./test-schemes.js');

const lab = exports.lab = Lab.script();
const {
    describe,
    it,
    before,
    beforeEach
} = lab;
const { expect } = Code;

let server;
let requestOpts;
let stubbedClientAddress;

const addRoutes = (serverInstance, nums, pass) => {

    const ipWhitelistRouteConfig = (num) => ({
        auth: {
            strategies: [`test-ip-whitelist${num}`, `always-${pass ? 'pass' : 'fail'}`]
        },
        handler: async (req, h) => ({ success: true }),
        ext: {
            onPreAuth: {
                method: (req, h) => {

                    req.info.remoteAddress = stubbedClientAddress;
                    return h.continue;
                }
            }
        }
    });
    nums.forEach((num) => {

        serverInstance.route({
            method: 'GET',
            path: `/test${num}`,
            config: ipWhitelistRouteConfig(num)
        });
    });
};

describe('Hapi-ip-whitelist strategy instantiation', () => {

    beforeEach(async () => {

        server = Hapi.Server();
        await server.register(HapiIpWhitelist);
    });

    it('fails because of missing options', async () => {

        let error;
        try {
            server.auth.strategy('test-ip-whitelist1', 'ip-whitelist', {});
        }
        catch (err) {
            error = err;
        }

        expect(error).to.exist();
    });
    it('fails because of invalid networkAddress', async () => {

        let error;
        try {
            server.auth.strategy('test-ip-whitelist1', 'ip-whitelist', {
                networkAddress: '300.300.0.0',
                subnetMask: 16
            });
        }
        catch (err) {
            error = err;
        }

        expect(error).to.exist();
    });
    it('fails because of invalid type for networkAddress', async () => {

        let error;
        try {
            server.auth.strategy('test-ip-whitelist1', 'ip-whitelist', {
                networkAddress: 'random string',
                subnetMask: 16
            });
        }
        catch (err) {
            error = err;
        }

        expect(error).to.exist();
    });
    it('fails because of invalid subnetMask', async () => {

        let error;
        try {
            server.auth.strategy('test-ip-whitelist1', 'ip-whitelist', {
                networkAddress: '132.32.2.2',
                subnetMask: 'Nan'
            });
        }
        catch (err) {
            error = err;
        }

        expect(error).to.exist();
    });
    it('fails because of invalid validateFunction', async () => {

        let error;
        try {
            server.auth.strategy('test-ip-whitelist1', 'ip-whitelist', {
                networkAddress: '132.32.2.2',
                subnetMask: 16,
                validationFunction: 'string, not a function'
            });
        }
        catch (err) {
            error = err;
        }

        expect(error).to.exist();
    });
    it('fails because of invalid logger function', async () => {

        let error;
        try {
            server.auth.strategy('test-ip-whitelist1', 'ip-whitelist', {
                networkAddress: '132.32.2.2',
                subnetMask: 16,
                logger: 'string, not a function'
            });
        }
        catch (err) {
            error = err;
        }

        expect(error).to.exist();
    });
});

describe('Hapi-ip-whitelist filter logic', () => {

    before(async () => {

        server = Hapi.Server();
        await server.register(HapiIpWhitelist);
        await server.register(TestSchemes);

        server.auth.strategy('test-ip-whitelist1', 'ip-whitelist', {
            networkAddress: '172.24.0.0',
            subnetMask: 16,
            forwardToNextStrategy: true
        });
        server.auth.strategy('test-ip-whitelist2', 'ip-whitelist', {
            networkAddress: '192.143.0.0',
            subnetMask: 14,
            forwardToNextStrategy: true
        });
        server.auth.strategy('test-ip-whitelist3', 'ip-whitelist', {
            networkAddress: '192.143.0.0',
            subnetMask: 16,
            forwardToNextStrategy: false
        });
        server.auth.strategy('test-ip-whitelist4', 'ip-whitelist', {
            networkAddress: '192.168.0.0',
            subnetMask: 16,
            forwardToNextStrategy: true
        });
        server.auth.strategy('always-pass', 'always-pass');
        server.auth.strategy('always-fail', 'always-fail');

        addRoutes(server, [1, 2], true);
        addRoutes(server, [3, 4], false);
    });

    describe('Request is processed by test-ip-whitelist strategy followed by second strategy with that authorizes user', () => {

        describe('Testing /test1 route', () => {

            before(async () => {

                requestOpts = {
                    method: 'GET',
                    url: '/test1'
                };
            });

            describe('User ip address has valid network part', () => {

                it('authorizes user', async () => {

                    stubbedClientAddress = '172.24.4.4';
                    const res = await server.inject(requestOpts); console.log(res);
                    expect(res.statusCode).to.equal(200);
                    expect(res.result.success).equals(true);
                });
                it('authorizes user', async () => {

                    stubbedClientAddress = '172.24.0.0';
                    const res = await server.inject(requestOpts);
                    expect(res.statusCode).to.equal(200);
                    expect(res.result.success).equals(true);
                });
                it('authorizes user', async () => {

                    stubbedClientAddress = '172.24.255.255';
                    const res = await server.inject(requestOpts);
                    expect(res.statusCode).to.equal(200);
                    expect(res.result.success).equals(true);
                });
            });
            describe('User ip address does not belong in required network range', () => {

                it('rejects user', async () => {

                    stubbedClientAddress = '172.18.4.4';
                    const res = await server.inject(requestOpts);
                    expect(res.statusCode).to.equal(401);
                    expect(res.result.message).equals('Forbidden access');
                });
                it('rejects user', async () => {

                    stubbedClientAddress = '192.0.1.4';
                    const res = await server.inject(requestOpts);
                    expect(res.statusCode).to.equal(401);
                    expect(res.result.message).equals('Forbidden access');
                });
                it('rejects user', async () => {

                    stubbedClientAddress = '172.35.4.4';
                    const res = await server.inject(requestOpts);
                    expect(res.statusCode).to.equal(401);
                    expect(res.result.message).equals('Forbidden access');
                });
            });
            describe('User has invalid ip address', () => {

                it('rejects user', async () => {

                    stubbedClientAddress = '30.3.0.300';
                    const res = await server.inject(requestOpts);
                    expect(res.statusCode).to.equal(401);
                    expect(res.result.message).equals('Forbidden access');
                });
            });
        });
        describe('Testing /test2 route', () => {

            before(async () => {

                requestOpts = {
                    method: 'GET',
                    url: '/test2'
                };
            });

            describe('User ip address has valid network part', () => {

                it('authorizes user', async () => {

                    stubbedClientAddress = '192.143.4.4';
                    const res = await server.inject(requestOpts);
                    expect(res.statusCode).to.equal(200);
                    expect(res.result.success).equals(true);
                });
                it('authorizes user', async () => {

                    stubbedClientAddress = '192.145.0.0';
                    const res = await server.inject(requestOpts);
                    expect(res.statusCode).to.equal(200);
                    expect(res.result.success).equals(true);
                });
            });
            describe('User ip address does not belong in required network range', () => {

                it('rejects user', async () => {

                    stubbedClientAddress = '172.18.4.4';
                    const res = await server.inject(requestOpts);
                    expect(res.statusCode).to.equal(401);
                    expect(res.result.message).equals('Forbidden access');
                });
                it('rejects user', async () => {

                    stubbedClientAddress = '192.149.1.4';
                    const res = await server.inject(requestOpts);
                    expect(res.statusCode).to.equal(401);
                    expect(res.result.message).equals('Forbidden access');
                });
            });
        });
    });
    describe('Authentication is only done by test-ip-whitelist strategy', () => {

        describe('Testing /test3 route', () => {

            before(async () => {

                requestOpts = {
                    method: 'GET',
                    url: '/test3'
                };
            });

            describe('User ip address has valid network part', () => {

                it('authorizes user', async () => {

                    stubbedClientAddress = '192.143.4.4';
                    const res = await server.inject(requestOpts);
                    expect(res.statusCode).to.equal(200);
                    expect(res.result.success).equals(true);
                });
            });
            describe('User ip address does not belong in required network range', () => {

                it('rejects user', async () => {

                    stubbedClientAddress = '192.149.1.4';
                    const res = await server.inject(requestOpts);
                    expect(res.statusCode).to.equal(401);
                    expect(res.result.message).equals('Forbidden access');
                });
            });
        });
    });
    describe('Request is processed by test-ip-whitelist strategy followed by second strategy that rejects the user', () => {

        describe('Testing /test4 route', () => {

            before(async () => {

                requestOpts = {
                    method: 'GET',
                    url: '/test4'
                };
            });

            describe('User ip address has valid network part', () => {

                it('gets rejected on next strategy', async () => {

                    stubbedClientAddress = '192.168.4.4';
                    const res = await server.inject(requestOpts);
                    expect(res.statusCode).to.equal(401);
                    expect(res.result.message).equals('Access denied');
                });
            });

            describe('User ip address does not belong in required network range', () => {

                it('gets rejected immediately', async () => {

                    stubbedClientAddress = '172.35.4.4';
                    const res = await server.inject(requestOpts);
                    expect(res.statusCode).to.equal(401);
                    expect(res.result.message).equals('Forbidden access');
                });
            });
        });
    });
});
