const Assert = require('assert');
const Boom = require('boom');
const Pkg = require('../package.json');

// The only way to move to next strategy on the route's list is to reply with Boom.unauthorized but with null value for message
// This is a semantical wrapper for it in order to convey more meaning
const approveAndPassToNextAuthStrategy = () => Boom.unauthorized(null, 'ip-whitelist');
const IP_REGEX =  /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
const splitIpQuartetsFrom = (ip) => IP_REGEX.exec(ip).splice(1, 4).map(Number);

const validateInternal = ({ networkIpQuartets, clientIpQuartets, networkSubnetMask }) => {
    const borderQuartetIndex = Math.floor(networkSubnetMask / 8);
    const borderQuartetNetworkValue = networkIpQuartets[borderQuartetIndex];
    const borderQuartetMaxClientValue = 2 ** (8 - (networkSubnetMask % 8));
    const sameNetworkPartAs = (networkQuartets) =>
        (quartet, index) => {
            const networkQuartet = networkQuartets[index];
            if (index < borderQuartetIndex) {
                return quartet === networkQuartet;
            }
            if (index === borderQuartetIndex) {
                return quartet >= networkQuartet
                    && quartet <= borderQuartetNetworkValue + borderQuartetMaxClientValue;
            }
            return true;
        };

    return clientIpQuartets.every(sameNetworkPartAs(networkIpQuartets));
};

const scheme = (server, options) => {
    
    Assert(options, 'Missing ip-whitelist auth strategy options');
    const {
        networkAddress,
        subnetMask,
        validateFunction,
        logger
    } = options;
    
    Assert(networkAddress, 'Hapi-ip-whitelist auth scheme options object missing network address');
    Assert(IP_REGEX.test(networkAddress), 'Hapi-ip-whitelist auth scheme network address invalid');
    Assert(subnetMask, 'Hapi-ip-whitelist auth scheme options object missing subnet mask');
    Assert(subnetMask > 8 && subnetMask < 30, 'Hapi-ip-whitelist auth scheme subnet mask invalid');
    Assert(!logger || typeof logger === 'function', 'Parameter logger must be a valid function if provided in hapi-ip-whitelist auth scheme options');
    Assert(
        !validateFunction || typeof validateFunction === 'function',
        'Parameter validateFunction must be a valid function if provided in hapi-ip-whitelist auth scheme options'
    );

    logger = logger || console.log;
    validateFunction = validateFunction || validateInternal;

    const networkIpQuartets = splitIpQuartetsFrom(networkAddress);
    
    return {
        authenticate: async (request, reply) => {
            
            try {
                const { remoteAddress } = request.info;
                if (!remoteAddress || !IP_REGEX.test(remoteAddress)) {
                    return reply(Boom.unauthorized('Forbidden access', 'ip-whitelist'));;
                }
                
                const clientIpQuartets = splitIpQuartetsFrom(remoteAddress);
                const params = { networkIpQuartets, clientIpQuartets, subnetMask };
                const isValid = await validateFunction(params);
                
                if (!isValid) {
                    return reply(Boom.unauthorized('Forbidden access', 'ip-whitelist'));
                }
                
                return reply(approveAndPassToNextAuthStrategy());
            }
            catch (err) {
                logger(err)
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