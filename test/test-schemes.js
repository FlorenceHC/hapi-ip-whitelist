'use strict';

const Boom = require('@hapi/boom');

const alwaysPassScheme = (server, options) => ({
    authenticate: async (request, h) => h.authenticated({ credentials: true })
});

const alwaysFailScheme = (server, options) => ({
    authenticate: async (request, h) => h.unauthenticated(Boom.unauthorized('Access denied'))
});

module.exports = {
    name: 'test-schemes',
    register: async (plugin) => {

        plugin.auth.scheme('always-pass', alwaysPassScheme);
        plugin.auth.scheme('always-fail', alwaysFailScheme);
    }
};
