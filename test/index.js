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

const serverInjectAsync = (opts) => new Promise(server.inject.bind(server, opts));
const serverRegisterAsync = (plugin) => new Promise(server.register.bind(server, plugin));

const addRoutes = (serverInstance, routeTypes, pass, proxy) => {

    const ipWhitelistRouteConfig = (type) => ({
        auth: {
            strategies: [`${type}`, `always-${pass ? 'pass' : 'fail'}`]
        },
        handler: (req, reply) => reply({ success: true }),
        ext: {
            onPreAuth: {
                method: (req, reply) => {

                    if (proxy) {
                        req.headers['x-forwarded-for'] = stubbedClientAddress;
                    }
                    else {
                        req.info.remoteAddress = stubbedClientAddress;
                    }

                    reply.continue();
                }
            }
        }
    });
    routeTypes.forEach((type) => {

        serverInstance.route({
            method: 'GET',
            path: `/${type}`,
            config: ipWhitelistRouteConfig(type)
        });
    });
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
    it('fails because of invalid addressWhitelist array', async () => {

        let error;
        try {
            server.auth.strategy('test-ip-whitelist1', 'ip-whitelist', {
                addressWhitelist: 4
            });
        }
        catch (err) {
            error = err;
        }

        expect(error).to.exist();
    });
    it('fails because of missing addressWhitelist and subnet', async () => {

        let error;
        try {
            server.auth.strategy('test-ip-whitelist1', 'ip-whitelist', {});
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

        server = new Hapi.Server();
        server.connection();
        await serverRegisterAsync(HapiIpWhitelist);
        await serverRegisterAsync(TestSchemes);

        server.auth.strategy('ip-whitelist-before-affirmative-strategy-1', 'ip-whitelist', {
            networkAddress: '172.24.0.0',
            subnetMask: 16
        });
        server.auth.strategy('ip-whitelist-before-affirmative-strategy-2', 'ip-whitelist', {
            networkAddress: '192.143.0.0',
            subnetMask: 14
        });
        server.auth.strategy('ip-whitelist-before-affirmative-strategy-3', 'ip-whitelist', {
            addressWhitelist: ['192.143.0.1', '192.143.10.10']
        });
        server.auth.strategy('ip-whitelist-before-affirmative-strategy-4', 'ip-whitelist', {
            networkAddress: '172.24.0.0',
            subnetMask: 16,
            addressWhitelist: ['192.143.0.1', '192.143.10.10']
        });
        server.auth.strategy('only-ip-whitelist', 'ip-whitelist', {
            networkAddress: '192.143.0.0',
            subnetMask: 16,
            forwardToNextStrategy: false
        });
        server.auth.strategy('ip-whitelist-before-failing-strategy', 'ip-whitelist', {
            networkAddress: '192.168.0.0',
            subnetMask: 16
        });
        server.auth.strategy('ip-whitelist-handling-proxied-request', 'ip-whitelist', {
            networkAddress: '172.24.0.0',
            subnetMask: 16,
            addressWhitelist: ['192.143.0.1', '192.143.10.10']
        });
        server.auth.strategy('always-pass', 'always-pass');
        server.auth.strategy('always-fail', 'always-fail');

        addRoutes(
            server,
            [
                'ip-whitelist-before-affirmative-strategy-1',
                'ip-whitelist-before-affirmative-strategy-2',
                'ip-whitelist-before-affirmative-strategy-3',
                'ip-whitelist-before-affirmative-strategy-4'
            ],
            true
        );
        addRoutes(server, ['only-ip-whitelist', 'ip-whitelist-before-failing-strategy'], false);
        addRoutes(server, ['ip-whitelist-handling-proxied-request'], true, true)
    });

    describe('Request is processed by test-ip-whitelist strategy followed by second strategy with that authorizes user', () => {

        describe('Validation is done only via subnet', () => {

            describe('Testing /ip-whitelist-before-affirmative-strategy-1 route', () => {

                before(async () => {

                    requestOpts = {
                        method: 'GET',
                        url: '/ip-whitelist-before-affirmative-strategy-1'
                    };
                });

                describe('User ip address has valid network part', () => {

                    it('authorizes user', async () => {

                        stubbedClientAddress = '172.24.4.4';
                        const res = await serverInjectAsync(requestOpts);
                        expect(res.statusCode).to.equal(200);
                        expect(res.result.success).equals(true);
                    });
                    it('authorizes user', async () => {

                        stubbedClientAddress = '172.24.0.0';
                        const res = await serverInjectAsync(requestOpts);
                        expect(res.statusCode).to.equal(200);
                        expect(res.result.success).equals(true);
                    });
                    it('authorizes user', async () => {

                        stubbedClientAddress = '172.24.255.255';
                        const res = await serverInjectAsync(requestOpts);
                        expect(res.statusCode).to.equal(200);
                        expect(res.result.success).equals(true);
                    });
                });

                describe('User ip address does not belong in required network range', () => {

                    it('rejects user', async () => {

                        stubbedClientAddress = '172.18.4.4';
                        const res = await serverInjectAsync(requestOpts);
                        expect(res.statusCode).to.equal(401);
                        expect(res.result.message).equals('Forbidden access');
                    });
                    it('rejects user', async () => {

                        stubbedClientAddress = '192.0.1.4';
                        const res = await serverInjectAsync(requestOpts);
                        expect(res.statusCode).to.equal(401);
                        expect(res.result.message).equals('Forbidden access');
                    });
                    it('rejects user', async () => {

                        stubbedClientAddress = '172.35.4.4';
                        const res = await serverInjectAsync(requestOpts);
                        expect(res.statusCode).to.equal(401);
                        expect(res.result.message).equals('Forbidden access');
                    });
                });
                describe('User has invalid ip address', () => {

                    it('rejects user', async () => {

                        stubbedClientAddress = '30.3.0.300';
                        const res = await serverInjectAsync(requestOpts);
                        expect(res.statusCode).to.equal(401);
                        expect(res.result.message).equals('Forbidden access');
                    });
                });
            });
            describe('Testing /ip-whitelist-before-affirmative-strategy-2 route', () => {

                before(async () => {

                    requestOpts = {
                        method: 'GET',
                        url: '/ip-whitelist-before-affirmative-strategy-2'
                    };
                });

                describe('User ip address has valid network part', () => {

                    it('authorizes user', async () => {

                        stubbedClientAddress = '192.143.4.4';
                        const res = await serverInjectAsync(requestOpts);
                        expect(res.statusCode).to.equal(200);
                        expect(res.result.success).equals(true);
                    });
                    it('authorizes user', async () => {

                        stubbedClientAddress = '192.145.0.0';
                        const res = await serverInjectAsync(requestOpts);
                        expect(res.statusCode).to.equal(200);
                        expect(res.result.success).equals(true);
                    });
                });

                describe('User ip address does not belong in required network range', () => {

                    it('rejects user', async () => {

                        stubbedClientAddress = '172.18.4.4';
                        const res = await serverInjectAsync(requestOpts);
                        expect(res.statusCode).to.equal(401);
                        expect(res.result.message).equals('Forbidden access');
                    });
                    it('rejects user', async () => {

                        stubbedClientAddress = '192.149.1.4';
                        const res = await serverInjectAsync(requestOpts);
                        expect(res.statusCode).to.equal(401);
                        expect(res.result.message).equals('Forbidden access');
                    });
                });
            });
        });
        describe('Validation is done only via addressWhitelist', () => {

            describe('Testing /ip-whitelist-before-affirmative-strategy-3 route', () => {

                before(async () => {

                    requestOpts = {
                        method: 'GET',
                        url: '/ip-whitelist-before-affirmative-strategy-3'
                    };
                });

                describe('User ip address belongs to the addressWhitelist', () => {

                    it('authorizes user', async () => {

                        stubbedClientAddress = '192.143.0.1';
                        const res = await serverInjectAsync(requestOpts);
                        expect(res.statusCode).to.equal(200);
                        expect(res.result.success).equals(true);
                    });
                    it('authorizes user', async () => {

                        stubbedClientAddress = '192.143.10.10';
                        const res = await serverInjectAsync(requestOpts);
                        expect(res.statusCode).to.equal(200);
                        expect(res.result.success).equals(true);
                    });
                });

                describe('User ip address does not belong to the addressWhitelist', () => {

                    it('rejects user', async () => {

                        stubbedClientAddress = '172.18.4.4';
                        const res = await serverInjectAsync(requestOpts);
                        expect(res.statusCode).to.equal(401);
                        expect(res.result.message).equals('Forbidden access');
                    });
                });

                describe('User has invalid ip address', () => {

                    it('rejects user', async () => {

                        stubbedClientAddress = '30.3.0.300';
                        const res = await serverInjectAsync(requestOpts);
                        expect(res.statusCode).to.equal(401);
                        expect(res.result.message).equals('Forbidden access');
                    });
                });
            });
        });
        describe('Validation is done only via subnet and via addressWhitelist', () => {

            describe('Testing /ip-whitelist-before-affirmative-strategy-4 route', () => {

                before(async () => {

                    requestOpts = {
                        method: 'GET',
                        url: '/ip-whitelist-before-affirmative-strategy-4'
                    };
                });

                describe('User ip address belongs to the subnet', () => {

                    it('authorizes user', async () => {

                        stubbedClientAddress = '172.24.0.5';
                        const res = await serverInjectAsync(requestOpts);
                        expect(res.statusCode).to.equal(200);
                        expect(res.result.success).equals(true);
                    });
                });

                describe('User ip address belongs to the addressWhitelist', () => {

                    it('authorizes user', async () => {

                        stubbedClientAddress = '192.143.0.1';
                        const res = await serverInjectAsync(requestOpts);
                        expect(res.statusCode).to.equal(200);
                        expect(res.result.success).equals(true);
                    });
                });

                describe('User ip address does not belong neither to subnet nor addressWhitelist', () => {

                    it('rejects user', async () => {

                        stubbedClientAddress = '172.11.4.4';
                        const res = await serverInjectAsync(requestOpts);
                        expect(res.statusCode).to.equal(401);
                        expect(res.result.message).equals('Forbidden access');
                    });
                });

                describe('User has invalid ip address', () => {

                    it('rejects user', async () => {

                        stubbedClientAddress = '30.3.0.300';
                        const res = await serverInjectAsync(requestOpts);
                        expect(res.statusCode).to.equal(401);
                        expect(res.result.message).equals('Forbidden access');
                    });
                });
            });
        });
    });
    describe('Authentication is only done by test-ip-whitelist strategy', () => {

        describe('Testing /only-ip-whitelist route', () => {

            before(async () => {

                requestOpts = {
                    method: 'GET',
                    url: '/only-ip-whitelist'
                };
            });

            describe('User ip address has valid network part', () => {

                it('authorizes user', async () => {

                    stubbedClientAddress = '192.143.4.4';
                    const res = await serverInjectAsync(requestOpts);
                    expect(res.statusCode).to.equal(200);
                    expect(res.result.success).equals(true);
                });
            });

            describe('User ip address does not belong in required network range', () => {

                it('rejects user', async () => {

                    stubbedClientAddress = '192.149.1.4';
                    const res = await serverInjectAsync(requestOpts);
                    expect(res.statusCode).to.equal(401);
                    expect(res.result.message).equals('Forbidden access');
                });
            });
        });
    });
    describe('Request is processed by test-ip-whitelist strategy followed by second strategy that rejects the user', () => {

        describe('Testing /ip-whitelist-before-failing-strategy route', () => {

            before(async () => {

                requestOpts = {
                    method: 'GET',
                    url: '/ip-whitelist-before-failing-strategy'
                };
            });

            describe('User ip address has valid network part', () => {

                it('gets rejected on next strategy', async () => {

                    stubbedClientAddress = '192.168.4.4';
                    const res = await serverInjectAsync(requestOpts);
                    expect(res.statusCode).to.equal(401);
                    expect(res.result.message).equals('Access denied');
                });
            });

            describe('User ip address does not belong in required network range', () => {

                it('gets rejected immediately', async () => {

                    stubbedClientAddress = '172.35.4.4';
                    const res = await serverInjectAsync(requestOpts);
                    expect(res.statusCode).to.equal(401);
                    expect(res.result.message).equals('Forbidden access');
                });
            });
        });
    });
    describe('Validation is done on the request that was forwarded by a proxy', () => {

        describe('Testing /ip-whitelist-handling-proxied-request route', () => {

            before(async () => {

                requestOpts = {
                    method: 'GET',
                    url: '/ip-whitelist-handling-proxied-request'
                };
            });

            describe('User ip address belongs to the subnet', () => {

                it('authorizes user', async () => {

                    stubbedClientAddress = '172.24.0.5';
                    const res = await serverInjectAsync(requestOpts);
                    expect(res.statusCode).to.equal(200);
                    expect(res.result.success).equals(true);
                });
            });

            describe('User ip address belongs to the addressWhitelist', () => {

                it('authorizes user', async () => {

                    stubbedClientAddress = '192.143.0.1';
                    const res = await serverInjectAsync(requestOpts);
                    expect(res.statusCode).to.equal(200);
                    expect(res.result.success).equals(true);
                });
            });

            describe('User ip address does not belong neither to subnet nor addressWhitelist', () => {

                it('rejects user', async () => {

                    stubbedClientAddress = '172.11.4.4';
                    const res = await serverInjectAsync(requestOpts);
                    expect(res.statusCode).to.equal(401);
                    expect(res.result.message).equals('Forbidden access');
                });
            });

            describe('User has invalid ip address', () => {

                it('rejects user', async () => {

                    stubbedClientAddress = '30.3.0.300';
                    const res = await serverInjectAsync(requestOpts);
                    expect(res.statusCode).to.equal(401);
                    expect(res.result.message).equals('Forbidden access');
                });
            });
        });
    });
});
