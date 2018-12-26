# Hapi-ip-whitelist

(**Note**: The Hapi-ip-whitelist v2.x is meant for use with Hapi v17. For Hapi v16 use v1.x)

This is an authentication scheme plugin for Hapi.js. Strategy defined with this scheme can be used before other strategies or as a standalone strategy. Although it is strongly recommended that this scheme is used only as an addition to other secure authentication mechanisms.

This strategy is applicable to both direct request and proxied request. Although for proxied requests it will only work for level 1 proxying i.e. for the requests that only pass through one proxy until they reach the server (This is a security measure because ip addressed from requests that go through several proxies can be easily spoofed). The client address in proxied requests is read from `x-forwarded-for` header for now only. 

The name of the registered scheme is `ip-whitelist`.

### Use case #1: Addition to other strategies
Put the strategy defined for this scheme to be first on the route you want to config. When the request arrives if the authentication is affirmative it will pass the request to other defined strategies, if not it will terminate request with code 401. This can be useful if you want to limit the requests to certain networks only, for example inside AWS VPC (Virtual Private Cloud).

The way this works is that if the ip address is invalid the strategy defined by this scheme will terminate the request calling `h.unauthenticated(Boom.unauthorized('message'))`, and if it is valid it will call `h.unauthenticated(Boom.unauthorized(null, 'ip-whitelist'))` passing it to other strategies defined on that specific route. Like it says in official Hapi documentation:

> When the scheme authenticate() method implementation throws an error or calls h.unauthenticated(), the specifics of the error affect whether additional authentication strategies will be attempted (if configured for the route). If the error includes a message, no additional strategies will be attempted. If the err does not include a message but does include the scheme name (e.g. Boom.unauthorized(null, 'Custom')), additional strategies will be attempted in the order of preference.

### Use case #2: Standalone strategy
When the request arrives if the authentication is affirmative it will authenticate user with
`{ credentials: userIpAddress }`, if not it will again terminate request with code 401.

## Registering plugin
```javascript
    const hapiIpWhitelist = require('hapi-ip-whitelist');
    
    const start = async () => {
        const server = Hapi.server();
        await server.register(hapiIpWhitelist);
    };

    start();
```
## Defining strategy
Options parameter (Hapi options used when defining strategy) for this strategy contains next properties:
- networkAddress - String (ex: '230.11.11.0') - Optional - Network address in which range requester's ip address must belong to
- subnetMask - Number (ex: 24) - Optional - Standard mask determines network part of the network address
- addressWhitelist - Array[Number] - Optional - Array of specific ip addresses that are whitelisted
- forwardToNextStrategy - Boolean - Optional (default: false) - Whether you want to prepend this strategy to others, or use it as a standalone
- logger - Function Object - Optional (default: console.log) - Function used for logging problems
  ```javascript
    function logger(msg) {
        console.log('Whitelist custom error message:' + msg);
    };
  ```

You must provide either `networkAddress` and `subnetMask` for the plugin to be able to check if the ip address is in the given network range, or you can provide `addressWhitelist` to explicitly allow some ip addresses. Or you can provide both, and the request will be forwarded for further processing if the client's address is either in provided subnet or whitelist array. But if you omit both of config options an error will be thrown since the plugin would not have a way to check address validity.

## Example
```javascript
    server.auth.strategy('custom-ip-whitelist-1', 'ip-whitelist', {
        networkAddress: '192.168.0.0',
        subnetMask: 16,
        forwardToNextStrategy: true,
        logger: someCustomLogger
    });

    server.auth.strategy('custom-ip-whitelist-2', 'ip-whitelist', {
        addressWhitelist: ['172.124.3.3', '172.124.3.4']
        forwardToNextStrategy: false,
        logger: someCustomLogger
    });

    server.auth.strategy('custom-ip-whitelist-3', 'ip-whitelist', {
        networkAddress: '192.168.0.0',
        subnetMask: 16,
        addressWhitelist: ['23.41.23.44', '23.41.23.45'],
        forwardToNextStrategy: true
    });
```
In this example, since internal validation function is used, every request with an ip address that belongs in the range determined by `networkAddress` and `subnetMask` will be valid, and the request will be forwarded to next authentication strategy.

