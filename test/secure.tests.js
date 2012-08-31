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

function getUser() {
  return { name : 'Dom' };
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
        usr.should.equal(user);
        done();
      });

      accessControl.createSession(getMockRequest(), user);
    });

  });
});