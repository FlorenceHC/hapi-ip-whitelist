'use strict';

const Hapi = require('hapi');
const Code = require('code');
const Lab = require('lab');

const HapiIpWhitelist = require('../lib/plugin.js');
const testSchemes = require('./test-schemes.js');

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

const serverInjectAsync = (opts) => new Promise(server.inject.bind(server, opts));
const serverRegisterAsync = (plugin) => new Promise(server.register.bind(server, plugin))

const addRoutes = (server, nums, pass) => {
    const ipWhitelistRouteConfig = (num) => ({
        auth: {
            strategies: [`test-ip-whitelist${num}`, `always-${pass ? 'pass' : 'fail'}`]
        },
        handler: (req, reply) => reply({ success: true }),
        ext: {
            onPreAuth: {
                method: (req, reply) => (req.info.remoteAddress = stubbedClientAddress, reply.continue())
            }
        }
    });
    nums.forEach(num => server.route({
        method: 'GET',
        path: `/test${num}`,
        config: ipWhitelistRouteConfig(num)
    }));
};

describe('Hapi-ip-whitelist strategy instantiation', () => {

    beforeEach(async () => {
        server = new Hapi.Server();
        server.connection();
        await serverRegisterAsync(HapiIpWhitelist);
    });

    it('fails because of missing options', async () => {
        let error;
        try {
            server.auth.strategy('test-ip-whitelist1', 'ip-whitelist', {});
        } catch (err) {
            error = err
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
        } catch (err) {
            error = err
        }
        expect(error).to.exist();
    });
    it('fails because of invalid networkAddress', async () => {
        let error;
        try {
            server.auth.strategy('test-ip-whitelist1', 'ip-whitelist', {
                networkAddress: 'random string',
                subnetMask: 16
            });
        } catch (err) {
            error = err
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
        } catch (err) {
            error = err
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
        } catch (err) {
            error = err
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
        } catch (err) {
            error = err
        }
        expect(error).to.exist();
    });
});

describe('Hapi-ip-whitelist filter logic', () => {

    before(async () => {
        server = new Hapi.Server();
        server.connection();
        await serverRegisterAsync(HapiIpWhitelist);
        await serverRegisterAsync(testSchemes);

        server.auth.strategy('test-ip-whitelist1', 'ip-whitelist', {
            networkAddress: '172.24.0.0',
            subnetMask: 16
        });
        server.auth.strategy('test-ip-whitelist2', 'ip-whitelist', {
            networkAddress: '192.143.0.0',
            subnetMask: 14
        });
        server.auth.strategy('test-ip-whitelist3', 'ip-whitelist', {
            networkAddress: '192.168.0.0',
            subnetMask: 16
        });
        server.auth.strategy('always-pass', 'always-pass');
        server.auth.strategy('always-fail', 'always-fail');

        addRoutes(server, [1, 2], true);
        addRoutes(server, [3], false)
    });

    describe('Testing vpc-ip-whitelist auth strategy before some other strategy that authorizes user', () => {

        describe('Testing /test1 route', () => {

            before(async () => {

                requestOpts = {
                    method: 'GET',
                    url: '/test1'
                };
            });

            describe('authorizes a user', () => {

                it('user ip address has valid network part #1', async () => {

                    stubbedClientAddress = '172.24.4.4';
                    const res = await serverInjectAsync(requestOpts);
                    expect(res.statusCode).to.equal(200);
                    expect(res.result.success).equals(true);
                });
                it('user ip address has valid network part #2', async () => {

                    stubbedClientAddress = '172.24.0.0';
                    const res = await serverInjectAsync(requestOpts);
                    expect(res.statusCode).to.equal(200);
                    expect(res.result.success).equals(true);
                });
                it('user ip address has valid network part #3', async () => {

                    stubbedClientAddress = '172.24.255.255';
                    const res = await serverInjectAsync(requestOpts);
                    expect(res.statusCode).to.equal(200);
                    expect(res.result.success).equals(true);
                });
            });
            describe('rejects user', () => {

                it('user ip address does not belong in required network range #1', async () => {

                    stubbedClientAddress = '172.18.4.4';
                    const res = await serverInjectAsync(requestOpts);
                    expect(res.statusCode).to.equal(401);
                    expect(res.result.message).equals('Forbidden access');
                });
                it('user ip address does not belong in required network range #2', async () => {

                    stubbedClientAddress = '192.0.1.4';
                    const res = await serverInjectAsync(requestOpts);
                    expect(res.statusCode).to.equal(401);
                    expect(res.result.message).equals('Forbidden access');
                });
                it('user ip address does not belong in required network range #3', async () => {

                    stubbedClientAddress = '172.35.4.4';
                    const res = await serverInjectAsync(requestOpts);
                    expect(res.statusCode).to.equal(401);
                    expect(res.result.message).equals('Forbidden access');
                });
                it('user has invalid ip address', async () => {

                    stubbedClientAddress = '30.3.0.300';
                    const res = await serverInjectAsync(requestOpts);
                    expect(res.statusCode).to.equal(401);
                    expect(res.result.message).equals('Forbidden access');
                });
            });
            describe('Testing /test2 route', () => {

                before(async () => {
    
                    requestOpts = {
                        method: 'GET',
                        url: '/test2'
                    };
                });
    
                describe('authorizes a user', () => {
    
                    it('user ip address has valid network part #1', async () => {
    
                        stubbedClientAddress = '192.143.4.4';
                        const res = await serverInjectAsync(requestOpts);
                        expect(res.statusCode).to.equal(200);
                        expect(res.result.success).equals(true);
                    });
                    it('user ip address has valid network part #2', async () => {
    
                        stubbedClientAddress = '192.145.0.0';
                        const res = await serverInjectAsync(requestOpts);
                        expect(res.statusCode).to.equal(200);
                        expect(res.result.success).equals(true);
                    });
                });
                describe('rejects user', () => {
    
                    it('user ip address does not belong in required network range #1', async () => {
    
                        stubbedClientAddress = '172.18.4.4';
                        const res = await serverInjectAsync(requestOpts);
                        expect(res.statusCode).to.equal(401);
                        expect(res.result.message).equals('Forbidden access');
                    });
                    it('user ip address does not belong in required network range #2', async () => {
    
                        stubbedClientAddress = '192.149.1.4';
                        const res = await serverInjectAsync(requestOpts);
                        expect(res.statusCode).to.equal(401);
                        expect(res.result.message).equals('Forbidden access');
                    });
                });
            });
        });
    });
    describe('Testing vpc-ip-whitelist auth strategy before strategy that rejects the user', () => {

        describe('Testing /test1 route', () => {

            before(async () => {

                requestOpts = {
                    method: 'GET',
                    url: '/test3'
                };
            });

            describe('rejects user', () => {

                it('user ip address has valid network part, but get rejected on next strategy', async () => {

                    stubbedClientAddress = '192.168.4.4';
                    const res = await serverInjectAsync(requestOpts);
                    expect(res.statusCode).to.equal(401);
                    expect(res.result.message).equals('Access denied');
                });
                it('user ip address does not belong in required network range, and gets rejected immediately', async () => {

                    stubbedClientAddress = '172.35.4.4';
                    const res = await serverInjectAsync(requestOpts);
                    expect(res.statusCode).to.equal(401);
                    expect(res.result.message).equals('Forbidden access');
                });
            });
        });
    });
});
