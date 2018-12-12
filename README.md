# Hapi-ip-whitelist
This is an authentication scheme plugin for Hapi.js. Strategy defined with this scheme can be used before other strategies. If the authentication is affirmative it will pass the request to other defined strategies, if not it will terminate request with code 401.

The name of the registered scheme is `ip-whitelist`.

User of this package must define some other strategy and append it next to this one, in order for any request to be successful.

## Registering plugin
```javascript
    const hapiIpWhitelist = require('hapi-ip-whitelist');
    const server = new Hapi.server();

    server.register(hapiIpWhitelist, err => err && console.log(err));
```
## Defining strategy
Options parameter (Hapi options used when defining strategy) for this strategy contains next properties:
- networkAddress - String (ex: '230.11.11.0') - Required - Network address which range requester's ip address must belong to
- subnetMask - Number (ex: 24) - Required - Standard mask determines network part of the network address
- logger - Function Object - Optional (default: console.log) - Function used for logging problems
  ```javascript
  function logger(msg) {
      console.log(msg);
  };
  ```
- validateFunction - Function Object - Optional (dafault: interlnalplugin function) - Custom function used to validate request with signature:
  ```javascript
  function validateFunction({networkAddress, subnetMask, clientAddress}) {
      
      /* do some work */

      return true || false; // Boolean determining wheter ip address is valid or not
  };
  ```
### Example:
```javascript
    server.auth.strategy('custom-ip-whitelist', 'ip-whitelist', {
        networkAddress: '192.168.0.0',
        subnetMask: 16,
        logger: someCustomLogger
    });
```
In this example, since internal validation function is used, every request with an ip address that belongs in the range determined by `networkAddress` and `subnetMask` will be valid, and the request will be forwarded to next authentication strategy.

