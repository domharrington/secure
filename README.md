# secure
ACL for Node.JS. Including authentication and express middleware for authorization.

[![build status](https://secure.travis-ci.org/domharrington/secure.png)](http://travis-ci.org/domharrington/secure)

## Installation

`npm install secure`

## Usage

### 1. Setup

Register the access control list:
````
var authenticatedAcl = require('secure/access-control-list')(customLogger)
````
You can define a custom logger and pass it through, else `console` will be used by default.

Add resources to the access control list:
````
authenticatedAcl.addResource('Admin')
````
This will add `create`, `read`, `update`, `delete`, and `*` as resource actions by default.


````
var accessControl = require('secure/access-control')(
  authenticationProvider, // Function to determine if user is authenticated
  authenticatedAcl, // Access control list for authenticated users
  unauthenticatedAcl, // Access control list for unauthenticated users (can use {} if not necessary)
  'admin', // Type, used to set req.session[type] for checking roles
  console, // Custom logger, if used
  function(req, res) {
    // Default failure callback
    res.redirect('/login')
  })
````

### 2. Middleware ACL

Add middleware to redirect users trying to access a resource without the appropriate permissions to a failure URL:
````
app.get(
  '/secure/',
  accessControl.requiredAccess(resource, action, failureUrl),
  function(req, res) {
    ...
  }
)
````

### 3. Non-middleware ACL Checks

The ACL can also be checked from within functions, rather than through middleware, for resource/action-specific functionality:
````
accessControl.isAllowed(req, resource, action) // Returns true/false
````

## Credits
[Dom Harrington](https://github.com/domharrington/)

[Paul Serby](https://github.com/serby/)

[Luke Wilde](https://github.com/lukewilde/)

## Licence
Licenced under the [New BSD License](http://opensource.org/licenses/bsd-license.php)
