'use strict';

const Assert = require('assert');
const Boom = require('@hapi/boom');
const Pkg = require('../package.json');

const IP_REGEX = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;

// Semantical wrapper for the only way to forward req to the next strategy on the route's list
const passToNextStrategy = () => Boom.unauthorized(null, 'ip-whitelist');
const finishAuthentication = (address) => ({ credentials: address });
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
        authenticate: async (request, h) => {

            try {
                let clientAddress;
                const xFFHeader = request.headers['x-forwarded-for'];
                const xFFHeaderAddresses = xFFHeader && xFFHeader.split(',');

                if (xFFHeaderAddresses) {
                    clientAddress = xFFHeaderAddresses[xFFHeaderAddresses.length - 1];
                }
                else {
                    clientAddress = request.info.remoteAddress;
                }

                if (!clientAddress || !IP_REGEX.test(clientAddress)) {
                    logger('Something went wrong. Hapi could not read clients ip address');
                    return h.unauthenticated(Boom.unauthorized('Forbidden access', 'ip-whitelist'));
                }

                const belongsToProvidedSubnet = isSubnetValid && belongsToSubnet({ networkAddress, clientAddress, subnetMask });
                const matchesProvidedWhitelist = isWhitelistValid && addressWhitelist.some(matchAddress(clientAddress));

                if (!belongsToProvidedSubnet && !matchesProvidedWhitelist) {
                    return h.unauthenticated(Boom.unauthorized('Forbidden access', 'ip-whitelist'));
                }

                return forwardToNextStrategy ?
                    h.unauthenticated(passToNextStrategy()) :
                    h.authenticated(finishAuthentication(clientAddress));
            }
            catch (err) {
                logger(err);
                throw Boom.internal();
            }
        }
    };
};


module.exports = {
    pkg: Pkg,
    register: async (plugin) => {

        plugin.auth.scheme('ip-whitelist', scheme);
    }
};
