var _ = require('underscore')
  ;

function getAcl(resource) {
  var acl = require('..').createAccessControlList({
    verbose: function() {
      return null;
    }
  });

  if (resource) {
    acl.addResource(resource);
  }

  return acl;
}

describe('access-control-list', function() {

  describe('#addResource()', function() {
    it('should add resources to acl', function() {
      var acl = getAcl()
        ;

      for (var i = 0; i < 100; i += 1) {
        var resource = 'test' + i
          ;

        acl.addResource(resource);
        acl.acl.hasOwnProperty(resource).should.equal(true);
      }

    });

    it('should have a default actionList of CRUD & *', function() {
      var acl = getAcl('hello')
        ;

      ['create', 'read', 'update', 'delete', '*'].forEach(function(action) {
        acl.acl.hello.actions.hasOwnProperty(action).should.equal(true);
      });
    });

    it('should be able to overwrite default actionList', function() {
      var acl = getAcl()
        , actions = ['action1', 'action2', 'action3']
        ;

      acl.addResource('hello', {
        actions: actions
      });

      actions.forEach(function(action) {
        acl.acl.hello.actions.hasOwnProperty(action).should.equal(true);
      });

      // Ensuring no extra actions get added
      Object.keys(acl.acl.hello.actions).forEach(function(action) {
        (actions.indexOf(action) > -1).should.equal(true);
      });
    });

    it('should be able to add a resource description', function() {
      var acl = getAcl()
        , description = 'test description'
        ;

      acl.addResource('hello', {
        description: description
      });

      acl.acl.hello.description.should.equal(description);
    });

    it('should default to no description', function() {
      var acl = getAcl('hello')
        ;

      acl.acl.hello.hasOwnProperty('description').should.equal(false);
    });
  });

  describe('#clearGrants()', function() {

    it('should clear all grants attached to the acl', function() {
      var acl = getAcl('resource')
        , i
        ;

      for (i = 0; i < 100; i += 1) {
        acl.addResource(i);
      }

      for (i = 0; i < 100; i += 1) {

        acl.grant(i + '-target', i, 'read');
      }

      acl.clearGrants();

      Object.keys(acl.acl).forEach(function(resource) {
        Object.keys(acl.acl[resource].actions).forEach(function(action) {
          acl.acl[resource][action].length.should.equal(0);
        });
      });

    });

  });

  describe('#grant()', function() {

    it('should add grants', function() {
      var acl = getAcl()
        , grantsLength = 100
        , resource = 'Admin'
        , action = 'read'
        ;

      acl.addResource(resource);
      for (var i = 0; i < grantsLength; i += 1) {
        acl.grant(i, resource, action);
        (acl.acl[resource].actions[action].indexOf(i) > -1).should.equal(true);
      }

      acl.acl[resource].actions[action].length.should.equal(grantsLength);
    });


    it('should throw if resource is unknown', function() {
      var acl = getAcl()
        , fakeResource = 'unknown-resource'
        ;

      (function() {
        acl.grant('target', fakeResource, 'action');
      }).should.throw('Unknown resource: ' + fakeResource);
    });

    it('should throw if action is unknown');

    it('should not add the same grant more than once', function() {
      var acl = getAcl('test')
        ;

      acl.grant('target', 'test', 'read');
      acl.grant('target', 'test', 'read');

      acl.acl.test.actions.read.length.should.equal(1);
      acl.acl.test.actions.read[0].should.equal('target');
    });

  });

  describe('#revoke()', function() {

    it('should revoke access', function() {
      var target = 'target'
        , resource = 'test'
        , action = 'read'
        , acl = getAcl(resource)
        ;

      acl.grant(target, resource, action);
      acl.revoke(target, resource, action);

      acl.allowed(target, resource, action).should.equal(false);
    });

    it('should throw if resource is unknown', function() {
      var acl = getAcl()
        , fakeResource = 'unknown-resource'
        ;

      (function() {
        acl.revoke('target', fakeResource, 'action');
      }).should.throw('Unknown resource: ' + fakeResource);
    });

    it('should throw if action is unknown', function() {
      var resource = 'resource'
        , unknownAction = 'unknown-action'
        , acl = getAcl(resource)
        ;

      (function() {
        acl.revoke('target', resource, unknownAction);
      }).should.throw('Unknown action: ' + unknownAction);
    });

  });

  describe('#allowed()', function() {

    it('should allow access to granted resources', function() {
      var acl = getAcl('Admin')
        ;

      acl.grant('jim', 'Admin', 'read');
      acl.allowed('jim', 'Admin', 'read').should.equal(true);
    });

    it('should disallow access to unknown resources', function() {
      var acl = getAcl()
        ;

      acl.allowed('jim', 'Unknown resource', 'read').should.equal(false);
    });

    it('should disallow access to undefined resources when others are defined', function() {
      var acl = getAcl('Admin')
        ;

      acl.grant('jim', 'Admin', 'read');
      acl.allowed('jim', 'Unknown resource', 'read').should.equal(false);
    });

    it('should disallow access to resources granted to users other than the subject', function() {
      var acl = getAcl('Admin')
        ;

      acl.grant('jane', 'Admin', 'read');
      acl.allowed('jim', 'Admin', 'read').should.equal(false);
    });

    it('should disallow update access to a resource only read access has been granted to', function() {
      var acl = getAcl('Admin')
        ;

      acl.grant('jim', 'Admin', 'read');
      acl.allowed('jim', 'Admin', 'update').should.equal(false);
    });

    it('should allow update access to a resource when * is granted', function() {
      var acl = getAcl('Admin')
        ;

      acl.grant('jim', 'Admin', '*');
      acl.allowed('jim', 'Admin', 'update').should.equal(true);
    });

    it('should disallow update access to an unknown resources when * is granted to an unrelated resource', function() {
      var acl = getAcl('Admin')
        ;

      acl.grant('jim', 'Admin', '*');
      acl.allowed('jim', 'Unknown', 'update').should.equal(false);
    });

    it('should disallow update access to other resources when * is granted to an unrelated resource', function() {
      var acl = getAcl('Admin')
        ;

      acl.addResource('Other');
      acl.grant('jim', 'Admin', '*');
      acl.allowed('jim', 'Other', 'read').should.equal(false);
    });

    it('should disallow case insensitive resource', function() {
      var acl = getAcl('Admin')
        ;

      acl.grant('jim', 'Admin', '*');
      acl.allowed('jim', 'admin', 'read').should.equal(false);
    });

    it('should allow access to anything using wildcard resource/action', function() {
      var acl = getAcl('Admin')
        ;

      acl.grant('jim', '*', '*');
      for (var i = 0; i < 100; i += 1) {
        acl.allowed('jim', i + '-resource', i + '-action').should.equal(true);
      }
    });

    it('should allow array of targets to be passed in and return true if any one passes', function() {
      var acl = getAcl('Admin')
        ;

      acl.grant('jim', 'Admin', 'read');

      acl.allowed(['fake-target', 'jim'], 'Admin', 'read').should.equal(true);
    });

  });

});

var emptyFn = function() {};

function getAccessControl(options) {

  options = options || {};

  options = _.extend({
    authenticationProvider: emptyFn,
    authenticatedAcl: getAcl(),
    unauthenticatedAcl: getAcl(),
    logger: {
      silly: emptyFn,
      info: emptyFn,
    }
  }, options);

  return require('..').createAccessControl(
    options.authenticationProvider,
    options.authenticatedAcl,
    options.unauthenticatedAcl,
    options.type,
    options.logger,
    options.defaultFailure
  );
}

function getMockRequest() {
  return {
    session: {}
  };
}

function getMockResponse() {
  var cookie = {};

  return {
    cookie: function(name, value) {
      cookie.name = name;
      cookie.value = value;
    },
    getCookie: function() {
      return cookie;
    },
    clearCookie: emptyFn
  };
}

function getUser() {
  return {
    name : 'Dom',
    emailAddress: 'dom@harrington-mail.com'
  };
}

describe('access-control', function() {

  it('should throw if authenticationProvider is not provided', function() {
    (function() {
      require('..').createAccessControl();
    }).should.throw('authenticationProvider is required and must be a function');
  });

  it('should error if authenticationProvider is not a function', function() {
    (function() {
      require('..').createAccessControl('');
    }).should.throw('authenticationProvider is required and must be a function');
  });

  it('should error if authenticatedAcl is not provided', function() {
    (function() {
      require('..').createAccessControl(emptyFn);
    }).should.throw('authenticatedAcl is required and must be an object');
  });

  it('should error if authenticatedAcl is not an object', function() {
    (function() {
      require('..').createAccessControl(emptyFn, '');
    }).should.throw('authenticatedAcl is required and must be an object');
  });

  it('should error if unauthenticatedAcl is not provided', function() {
    (function() {
      require('..').createAccessControl(emptyFn, {});
    }).should.throw('unauthenticatedAcl is required and must be an object');
  });

  it('should error if unauthenticatedAcl is not an object', function() {
    (function() {
      require('..').createAccessControl(emptyFn, {}, '');
    }).should.throw('unauthenticatedAcl is required and must be an object');
  });

  describe('#createSession()', function() {

    it('should add a property to the session which is equal to the accessControl type', function() {
      var accessControl
        , type = 'testType'
        ;

      accessControl = getAccessControl({
        type: type
      });

      var request = getMockRequest();

      accessControl.createSession(request, {});

      request.session.hasOwnProperty(type).should.equal(true);
    });

    it('should add the user to the type property of the session', function() {
      var accessControl = getAccessControl()
        , request = getMockRequest()
        , user = getUser()
        ;

      accessControl.createSession(request, user);

      request.session.user.should.equal(user);
    });

    it('should add a type + `JustLoggedIn` property to the session and set it to true', function() {
      var accessControl = getAccessControl()
        , request = getMockRequest()
        ;

      accessControl.createSession(request, {});

      request.session.hasOwnProperty('userJustLoggedIn').should.equal(true);
      request.session.userJustLoggedIn.should.equal(true);
    });

    it('should emit a session event with the user', function(done) {
      var accessControl = getAccessControl()
        , user = getUser()
        ;

      accessControl.on('session', function(usr) {
        usr.should.eql(user);
        done();
      });

      accessControl.createSession(getMockRequest(), user);
    });

  });

  describe('#authenticate()', function() {

    function authenticate(credentials, callback) {
      if (credentials.emailAddress === 'dom@harrington-mail.com') {
        callback(null, _.extend(getUser(), { authenticationId: 'test-auth-id' }));
      } else {
        callback(new Error('Wrong Email and password combination.'));
      }
    }

    it('should return an error if the authenticationProvider fails auth', function(done) {
      var accessControl = getAccessControl({ authenticationProvider: authenticate })
        ;

      accessControl.authenticate(
        getMockRequest(),
        getMockResponse(),
        { emailAddress: 'fake-user@test.com' },
        function(error, user) {
          error.message.should.equal('Wrong Email and password combination.');
          done();
        }
      );
    });

    it('should return the user if the authenticationProvider succeeds auth', function(done) {
      var accessControl = getAccessControl({ authenticationProvider: authenticate })
        , user = getUser()
        ;

      accessControl.authenticate(
        getMockRequest(),
        getMockResponse(),
        user,
        function(error, usr) {
          delete usr.authenticationId;
          usr.should.eql(user);
          done();
        }
      );
    });

    it('should create a session if auth succeeds', function(done) {
      var accessControl = getAccessControl({ authenticationProvider: authenticate })
        , user = getUser()
        , request = getMockRequest()
        ;

      accessControl.authenticate(
        request,
        getMockResponse(),
        user,
        function(error, usr) {
          request.session.user.should.eql(usr);
          done();
        }
      );
    });

    it('should create an auto authentication cookie if `rememberMe` credential is set', function(done) {
      var accessControl = getAccessControl({ authenticationProvider: authenticate })
        , user = getUser()
        , response = getMockResponse()
        ;

      accessControl.authenticate(
        getMockRequest(),
        response,
        _.extend(user, { rememberMe: true }),
        function(error, usr) {
          var cookie = response.getCookie();

          cookie.should.not.equal({});
          done();
        }
      );
    });

    it('should emit an authenticate event with the authed user', function(done) {
      var accessControl
        , user = getUser()
        ;

      accessControl = getAccessControl({
        authenticationProvider: authenticate
      });

      accessControl.on('authenticate', function(usr) {
        delete usr.authenticationId;
        usr.should.eql(user);
        done();
      });

      accessControl.authenticate(getMockRequest(), getMockResponse(), user, emptyFn);
    });

  });

  describe('#isAuthenticated()', function() {

    it('should return true for an authed session', function() {
      var accessControl = getAccessControl()
        ;

      accessControl.isAuthenticated({
        session: {
          user: {}
        }
      }).should.equal(true);
    });

    it('should return false for an unauthed session', function() {
      var accessControl = getAccessControl()
        ;

      accessControl.isAuthenticated(getMockRequest()).should.equal(false);
    });

  });

  describe('#canAutoAuthenticate()', function() {

    it('should return true if a user can auto authenticate', function() {
      var accessControl = getAccessControl()
        ;

      accessControl.canAutoAuthenticate({
        session: {
          user: {}
        },
        cookies: {
          userAuthenticationId: {}
        }
      }).should.equal(true);
    });

    it('should return false if a user can not auto authenticate', function() {
      var accessControl = getAccessControl()
        ;

      accessControl.canAutoAuthenticate({
        session: {
          user: {}
        },
        cookies: {}
      }).should.equal(false);
    });

  });

  describe('#setAutoAuthenticationCookie()', function() {

    it('sets auto authentication cookie on the response using res#cookie()', function() {
      var accessControl = getAccessControl()
        , response = getMockResponse()
        , authId = 'test-auth-id'
        ;

      accessControl.setAutoAuthenticationCookie(response, {
        authenticationId: authId
      });

      var cookie = response.getCookie();

      cookie.name.should.equal('userAuthenticationId');
      cookie.value.should.equal(authId);
    });

  });

  describe('#clearAutoAuthenticationCookie()', function() {

    it('calls the clearCookie method of the response object', function() {
      var accessControl = getAccessControl()
        , called = false
        ;

      accessControl.clearAutoAuthenticationCookie({
        // Creating a mock clearCookie function
        clearCookie: function(name) {
          name.should.equal('userAuthenticationId');
          called = true;
        }
      });

      called.should.equal(true);
    });

  });

  describe('#isAllowed()', function() {

    it('should return false if session variable isnt set', function() {
      var accessControl = getAccessControl()
        ;

      accessControl.isAllowed(getMockRequest(), 'test', 'test').should.equal(false);
    });

    it('should use authenticatedAcl if session has a roles property', function() {
      var accessControl
        , request = getMockRequest()
        , called = false
        ;

      accessControl = getAccessControl({
        authenticatedAcl: {
          allowed: function() {
            called = true;
          }
        }
      });

      request.session = {
        user: {
          roles: []
        }
      };

      accessControl.isAllowed(request, 'test', 'test');

      called.should.equal(true);
    });

    it('should use unauthenticatedAcl if session doesn\'t have a roles property', function() {
      var accessControl
        , request = getMockRequest()
        , called = false
        ;

      accessControl = getAccessControl({
        unauthenticatedAcl: {
          allowed: function() {
            called = true;
          }
        }
      });

      request.session = {
        user: {}
      };

      accessControl.isAllowed(request, 'test', 'test');

      called.should.equal(true);
    });

  });

  describe('#destroy()', function() {

    it('should emit a destroy event', function(done) {
      var accessControl = getAccessControl()
        , user = getUser()
        , response = getMockResponse()
        ;

      accessControl.on('destroy', function(usr) {
        done();
      });

      accessControl.destroy(getMockRequest(), response);
    });

    it('should delete the user from the session', function() {
      var accessControl = getAccessControl()
        , request = getMockRequest()
        ;

      request.session.user = {
        a: 'b',
        c: 'd'
      };

      accessControl.destroy(request, getMockResponse());

      request.session.should.eql({});
    });

    it('should call clearAutoAuthenticationCookie()', function() {
      var accessControl = getAccessControl()
        , called = false
        ;

      accessControl.destroy(getMockRequest(), {
        clearCookie: function() {
          called = true;
        }
      });

      called.should.equal(true);
    });

  });

  describe('#setBlockedRequest()', function() {

    it('should add a type + `LastUrl` property to the session', function() {
      var accessControl = getAccessControl()
        , request = getMockRequest()
        , url = '/test-url'
        ;

      request.url = url;

      accessControl.setBlockedRequest(request);

      request.session.userLastUrl.should.equal(url);
    });

  });

  describe('#getLastBlockedUrl()', function() {

    it('should retrieve the type + `LastUrl` from the session', function() {
      var accessControl = getAccessControl()
        , request = getMockRequest()
        , url = '/test-url'
        ;

      request.session.userLastUrl = url;

      accessControl.getLastBlockedUrl(request).should.equal(url);
    });

  });

  describe('#requiredAccess()', function() {

    it('should return a function', function() {
      var accessControl = getAccessControl()
        ;

      (typeof accessControl.requiredAccess('test', 'test', 'test')).should.equal('function');
    });

    it('should call next() if the request is allowed', function() {
      var accessControl
        , called = false
        , request = getMockRequest()
        ;

      accessControl = getAccessControl({
        authenticatedAcl: {
          // Mocking an acl allowed function that always returns true
          allowed: function() {
            return true;
          }
        }
      });

      request.session.user = {
        roles: []
      };

      var middleware = accessControl.requiredAccess('test', 'test', 'test');

      middleware(request, getMockResponse(), function() {
        called = true;
      });

      called.should.equal(true);
    });

    it('should call redirect on the response if failure is a string', function() {
      var accessControl = getAccessControl()
        , called = false
        , response = getMockResponse()
        , failure = 'test-failure'
        ;

      // Mocking express' redirect function
      response.redirect = function(fail) {
        fail.should.equal(failure);
        called = true;
      };

      var middleware = accessControl.requiredAccess('test', 'test', failure);

      middleware(getMockRequest(), response, emptyFn);

      called.should.equal(true);
    });

    it('should call failure if it is a function', function() {
      var accessControl = getAccessControl()
        , called = false
        ;

      function failure() {
        called = true;
      }

      var middleware = accessControl.requiredAccess('test', 'test', failure);

      middleware(getMockRequest(), getMockResponse(), emptyFn);

      called.should.equal(true);
    });

    it('should call defaultFailure if no failure passed in', function() {
      var accessControl
        , called = false
        ;

      accessControl = getAccessControl({
        defaultFailure: function() {
          called = true;
        }
      });

      var middleware = accessControl.requiredAccess('test', 'test');

      middleware(getMockRequest(), getMockResponse(), emptyFn);

      called.should.equal(true);
    });

  });

});