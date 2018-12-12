'use strict';

const Boom = require('boom');

const alwaysPassScheme = (server, options) => ({
        authenticate: (request, reply) => reply.continue({ credentials: true })
});

const alwaysFailScheme = (server, options) => ({
    authenticate: (request, reply) => reply(Boom.unauthorized('Access denied'))
});

exports.register = (plugin, options, next) => {
    plugin.auth.scheme('always-pass', alwaysPassScheme);
    plugin.auth.scheme('always-fail', alwaysFailScheme);
    next();
};
exports.register.attributes = { name: 'testSchemes' };
