'use strict';

const Assert = require('assert');
const Boom = require('boom');
const Pkg = require('../package.json');

const IP_REGEX = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;

// Semantical wrapper for the only way to forward req to the next strategy on the route's list
const approveAndPassToNextStrategy = () => Boom.unauthorized(null, 'ip-whitelist');
const approveAndFinishAuthentication = (address) => ({ credentials: address });
const splitIpQuartetsFrom = (ip) => IP_REGEX.exec(ip).splice(1, 4).map(Number);

const matchAddress = (ip) => {

    return (whitelistIp) => ip === whitelistIp;
};

const belongsToSubnet = ({ networkAddress, clientAddress, subnetMask }) => {

    const networkIpQuartets = splitIpQuartetsFrom(networkAddress);
    const clientIpQuartets = splitIpQuartetsFrom(clientAddress);

    const borderQuartetIndex = Math.floor(subnetMask / 8);
    const borderQuartetNetworkValue = networkIpQuartets[borderQuartetIndex];
    const borderQuartetMaxClientValue = 2 ** (8 - (subnetMask % 8));

    const sameNetworkPartAs = (networkQuartets) => {

        return (quartet, index) => {

            const networkQuartet = networkQuartets[index];

            if (index < borderQuartetIndex) {
                return quartet === networkQuartet;
            }

            if (index === borderQuartetIndex) {
                return quartet >= networkQuartet && quartet <= borderQuartetNetworkValue + borderQuartetMaxClientValue;
            }

            return true;
        };
    };

    return clientIpQuartets.every(sameNetworkPartAs(networkIpQuartets));
};

const scheme = (server, options) => {

    Assert(Object.keys(options).length, 'Missing ip-whitelist auth strategy options');
    let {
        networkAddress,
        subnetMask,
        addressWhitelist = [],
        forwardToNextStrategy = true,
        logger
    } = options;

    let isSubnetValid = false;
    let isWhitelistValid = false;

    Assert(
        (networkAddress && subnetMask) || addressWhitelist.length,
        'Hapi-ip-whitelist auth scheme does not have configured neither valid subnet nor single ip addresses'
    );

    if (networkAddress && subnetMask) {
        Assert(IP_REGEX.test(networkAddress), 'Hapi-ip-whitelist auth scheme network address invalid');
        Assert(subnetMask >= 8 && subnetMask <= 30, 'Hapi-ip-whitelist auth scheme subnet mask invalid');
        isSubnetValid = true;
    }

    if (addressWhitelist.length) {
        Assert(
            addressWhitelist.every(IP_REGEX.test.bind(IP_REGEX)),
            'Hapi-ip-whitelist auth scheme addressWhitelist array contains invalid ip addresses'
        );
        isWhitelistValid = true;
    }

    Assert(
        !logger || typeof logger === 'function',
        'Parameter logger must be a valid function if provided in hapi-ip-whitelist auth scheme options'
    );

    logger = logger || console.log;

    return {
        authenticate: async (request, reply) => {

            try {
                const { remoteAddress: clientAddress } = request.info;
                if (!clientAddress || !IP_REGEX.test(clientAddress)) {
                    return reply(Boom.unauthorized('Forbidden access', 'ip-whitelist'));
                }

                const belongsToProvidedSubnet = isSubnetValid && belongsToSubnet({ networkAddress, clientAddress, subnetMask });
                const matchesProvidedWhitelist = isWhitelistValid && addressWhitelist.some(matchAddress(clientAddress));

                if (!belongsToProvidedSubnet && !matchesProvidedWhitelist) {
                    return reply(Boom.unauthorized('Forbidden access', 'ip-whitelist'));
                }

                return forwardToNextStrategy ?
                    reply(approveAndPassToNextStrategy()) :
                    reply.continue(approveAndFinishAuthentication(clientAddress));
            }
            catch (err) {
                logger(err);
                return reply(Boom.internal('Internal error'));
            }
        }
    };
};


exports.register = (plugin, options, next) => {

    plugin.auth.scheme('ip-whitelist', scheme);
    next();
};

exports.register.attributes = { pkg: Pkg };
