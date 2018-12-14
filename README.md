# Hapi-ip-whitelist

This is an authentication scheme plugin for Hapi.js. Strategy defined with this scheme can be used before other strategies or as a standalone strategy. 
The name of the registered scheme is `ip-whitelist`.

### Use case #1: Addition to other strategies
Put the strategy defined for this scheme to be first on the route you want to config. When the request arrives if the authentication is affirmative it will pass the request to other defined strategies, if not it will terminate request with code 401. 

The way this works is that if the ip address is invalid the strategy defined by this scheme will terminate the request calling `reply(Boom.unauthorized('message'))`, and if it is valid it will call `reply(Boom.unauthorized(null, 'ip-whitelist'))` passing it to other strategies defined on that specific route. Like it says in official Hapi documentation:

> If the err passed to the reply() method includes a message, no additional strategies will be attempted. If the err does not include a message but does include the scheme name (e.g. Boom.unauthorized(null, 'Custom')), additional strategies will be attempted in the order of preference (defined in the route configuration).

### Use case #2: Standalone strategy
When the request arrives if the authentication is affirmative it will authenticate user with
`{ credentials: userIpAddress }`, if not it will again terminate request with code 401.


## Registering plugin
```javascript
    const hapiIpWhitelist = require('hapi-ip-whitelist');
    const server = new Hapi.server();

    server.register(hapiIpWhitelist, (err) => {
        if (err) {
            console.log(err);
        }
    );
```
## Defining strategy
Options parameter (Hapi options used when defining strategy) for this strategy contains next properties:
- networkAddress - String (ex: '230.11.11.0') - Required - Network address in which range requester's ip address must belong to
- subnetMask - Number (ex: 24) - Required - Standard mask determines network part of the network address
- forwardToNextStrategy - Boolean - Optional (default: false) - Whether you want to prepend this strategy to others, or use it as a standalone
- logger - Function Object - Optional (default: console.log) - Function used for logging problems
  ```javascript
    function logger(msg) {
        console.log(msg);
    };
  ```
- validationFunction - Function Object - Optional (dafault: interlnalplugin function) - Can be both async and a regular function. Must return Boolean or Promise that will resolve to Boolean. Example:
  ```javascript
    function async validationFunction({networkAddress, subnetMask, clientAddress}) {
      
        /* do some work */

        return true || false; // Boolean determining whether ip address is valid or not
    };
  ```
### Example:
```javascript
    server.auth.strategy('custom-ip-whitelist', 'ip-whitelist', {
        networkAddress: '192.168.0.0',
        subnetMask: 16,
        forwardToNextStrategy: true,
        logger: someCustomLogger
    });
```
In this example, since internal validation function is used, every request with an ip address that belongs in the range determined by `networkAddress` and `subnetMask` will be valid, and the request will be forwarded to next authentication strategy.

