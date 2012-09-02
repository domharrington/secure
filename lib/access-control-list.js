var _ = require('underscore')
  ;

module.exports = function(logger) {
  var acl = {
    '*': {
      actions: {
        '*': []
      }
    }
  };

  // Provides the console as a default logger
  logger = logger || {
    verbose: console.log
  };

  /**
   * Clears all grants attached to the ACL
   *
   * @api public
   */
  function clearGrants() {
    Object.keys(acl).forEach(function(resource) {
      Object.keys(acl[resource].actions).forEach(function(action) {
        acl[resource][action] = [];
      });
    });
  }

  /**
   * Adds a resource to the ACL. Throws an error if actions option is not
   * an Array.
   *
   * Action list defaults to: create, read, update, delete and *.
   *
   * @param {String} resource to add
   * @param {Object} resource options: action list & description
   * @api public
   */
  function addResource(resource, resourceOptions) {

    if (acl[resource] === undefined) {

      var options = {
        actions: ['create', 'read', 'update', 'delete', '*']
      };

      _.extend(options, resourceOptions);

      if (!Array.isArray(options.actions)) {
        throw new TypeError('actionList is excepted to be an array of action ' +
        'names that can be performed on the resource \'' + resource + '\'');
      }

      var actions = {};

      // Create a blank array for each action
      options.actions.forEach(function(action) {
        actions[action] = [];
      });

      logger.verbose('Adding resource \'' + resource + '\' to access control list');

      // Adding the resource to the ACL
      acl[resource] = {
        actions: actions
      };

      if (options.description) {
        acl[resource].description = options.description;
      }

    } else {
      logger.verbose('Resource \'' + resource + '\' already added');
    }
  }

  /**
   * Helper function to throw a RangeError if a given resource doesnt exist
   *
   * @param {String} resource
   * @api private
   */
  function throwIfResourceDoesntExist(resource) {
    // Ensure the resource has been added
    if (acl[resource] === undefined) {
      throw new RangeError('Unknown resource: ' + resource);
    }
  }

  /**
   * Grant a given target permission to perform the given action a resource
   *
   * @param {String} target
   * @param {String} resource
   * @param {String} action
   * @api public
   */
  function grant(target, resource, action) {
    throwIfResourceDoesntExist(resource);

    // if (acl[resource][action] === undefined) {
    //   throw new RangeError('Unknown action: ' + action);
    // }

    if (acl[resource].actions[action] === undefined) {
      acl[resource].actions[action] = [target];
    } else if (acl[resource].actions[action].indexOf(target) === -1) {
      acl[resource].actions[action].push(target);
    }
  }

  /**
   * Revoke a given target permission to access the given resource
   *
   * @param {String} target
   * @param {String} resource
   * @param {String} action
   * @api public
   */
  function revoke(target, resource, action) {
    throwIfResourceDoesntExist(resource);

    var targets = acl[resource].actions[action]
      ;

    if (targets === undefined) {
      throw new RangeError('Unknown action: ' + action);
    }

    targets.some(function(eachTarget, index) {
      if (target === eachTarget) {
        targets.splice(index, 1);
        return true;
      }
    });
  }

  /**
   * Checks if a given target is allowed access. Firstly checks if the acl has
   * a given resource, then checks that the resource has the given action,
   * finally checks if the target is in the granted targets array or if the
   * target is in the '*' group to be allowed all access.
   *
   * @param {String} target
   * @param {String} resource
   * @param {String} action
   * @api private
   */
  function targetAllowed(target, resource, action) {
    return acl[resource]
        && acl[resource].actions[action]
        && ((acl[resource].actions[action].indexOf(target) !== -1)
        || (acl[resource].actions['*'] && acl[resource].actions['*'].indexOf(target) !== -1));
  }

  /**
   * Check if a target is allowed access to a given resource/action.
   *
   * @param {Array} targets array of potential targets
   * @param {String} resource
   * @param {String} action
   * @api public
   */
  function allowed(targets, resource, action) {

    var target;

    if (!Array.isArray(targets)) {
      targets = [targets];
    }

    for (var i = 0; i < targets.length; i++) {

      target = targets[i];

      // Allow wildcard resource. This allows you to create a target with
      //    grant('root', '*', '*')
      // Who will always have access
      if (acl['*'].actions['*'].indexOf(target) !== -1) {
        return true;
      }

      if (targetAllowed(target, resource, action)) {
        return true;
      }
    }

    return false;
  }

  return {
    get acl() { return acl; },
    addResource: addResource,
    clearGrants: clearGrants,
    grant: grant,
    revoke: revoke,
    allowed: allowed
  };
};