var events = require('events')
  ;

/**
 * Creates an access control.
 *
 * @param {Function} authenticationProvider function to call to authenticate the user
 * @param {Object} authenticatedAcl ACL to use if the user is authed
 * @param {Object} unauthenticatedAcl ACL to use if the user is not authed
 * @param {String} type type of access control, defaults to 'user'
 * @param {Object} logger logger to use, defaults to `console`
 * @param {Function} defaultFailure default action to occur for a failure
 * @api public
 */
module.exports = function(authenticationProvider, authenticatedAcl, unauthenticatedAcl, type, logger, defaultFailure) {

  if (!authenticationProvider || typeof authenticationProvider !== 'function') {
    throw new Error('authenticationProvider is required and must be a function');
  }

  if (!authenticatedAcl || typeof authenticatedAcl !== 'object') {
    throw new Error('authenticatedAcl is required and must be an object');
  }

  if (!unauthenticatedAcl || typeof unauthenticatedAcl !== 'object') {
    throw new Error('unauthenticatedAcl is required and must be an object');
  }

  // This object will extend EventEmitter
  var self = new events.EventEmitter();

  // Failover to console based logging
  logger = logger || console;

  // Default type of authentication
  type = type || 'user';

  if (!defaultFailure) {
    defaultFailure = function(req, res, resource, action, next) {
      next(new Error('Unauthorized: ' + resource + ' / ' + action));
    };
  }

  /**
   * Builds the session object using the user provided. Used internally by
   * `authenticate`.
   *
   * @param {Object} req Request object
   * @param {Object} user The authenticated user
   * @api public
   */
  function createSession(req, user) {
    req.session[type] = user;

    req.session[type + 'JustLoggedIn'] = true;
    logger.info('Authenticated session created', req.session[type]);

    self.emit('session', user);
  }

  function setAutoAuthenticationCookie(res, user) {
    res.cookie(type + 'AuthenticationId', user.authenticationId, { path: '/', expired: 90000 });
  }

  function authenticate(req, res, credentials, callback) {
    logger.info('Authentication Attempt', credentials.emailAddress);
    authenticationProvider.authenticate(credentials, function(error, user) {
      if (error) {
        logger.info('Authentication Failed', credentials.emailAddress);
        return callback(error);
      }
      self.emit('authenticate', user);
      createSession(req, user);
      if (credentials.rememberMe) {
        setAutoAuthenticationCookie(res, user);
      }
      callback(null, user);
    });
  }

  function isAuthenticated(req) {
    return req.session && (req.session[type] !== undefined);
  }

  function canAutoAuthenticate(req) {
    var res = res;
    return isAuthenticated(req) && (res.cookie[type + 'AuthenticationId'] !== undefined);
  }

  function clearAutoAuthenticationCookie(res) {
    res.clearCookie(type + 'AuthenticationId');
  }

  function isAllowed(req, res, resource, action, callback) {
    if (!req.session[type]) {
      if ((callback) && (typeof callback === 'function')) {
        return callback(null, false);
      } else {
        return false;
      }
    }
    //TODO: Caching may give an improvement here
    if (req.session[type].roles) {
      return authenticatedAcl.allowed(req.session[type].roles, resource, action, callback);
    } else {
      return unauthenticatedAcl.allowed(req.session[type].roles, resource, action, callback);
    }
  }

  /**
   * Creates an Express middleware for managing access to a route.
   * @param {String} resource What is being accessed
   * @param {String} action The action that is being performed
   * @param {Mixed} failure Either a URL to redirect to on failure
   * @return {Function} Express middleware function
   */
  function requiredAccess(resource, action, failure) {
    return function(req, res, next) {

      isAllowed(req, res, resource, action, function(error, allowed) {
        if (allowed) {
          next();
        } else {
          logger.silly('Unauthorized: ' + resource + ' / ' + action);
          switch (typeof failure) {
            case 'string':
              return res.redirect(failure);
            case 'function':
              return failure();
            default:
              return defaultFailure(req, res, resource, action, next);
          }
        }
      });
    };
  }

  function destroy(req, res) {
    self.emit('destroy', req.session[type]);
    logger.info('Session Destroyed', req.session[type]);
    delete req.session[type];
    delete req.session[type + 'LastUrl'];
    clearAutoAuthenticationCookie(res);
  }

  function setBlockedRequest(req) {
    req.session[type + 'LastUrl'] = req.url;
  }

  function getLastBlockedUrl(req) {
    return req.session[type + 'LastUrl'];
  }

  self.createSession = createSession;
  self.authenticate = authenticate;
  self.isAuthenticated = isAuthenticated;
  self.canAutoAuthenticate = canAutoAuthenticate;
  self.setAutoAuthenticationCookie = setAutoAuthenticationCookie;
  self.clearAutoAuthenticationCookie = clearAutoAuthenticationCookie;
  self.isAllowed = isAllowed;
  self.destroy = destroy;
  self.setBlockedRequest = setBlockedRequest;
  self.getLastBlockedUrl = getLastBlockedUrl;
  self.requiredAccess = requiredAccess;

  return self;
};