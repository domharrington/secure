var mockLogger = {
  verbose: function() {
    return null;
  }
};

describe('acl', function() {
  describe('#allowed()', function() {

    it('should permit access to granted resources', function() {
      var acl = require('..').createAccessControlList(mockLogger);

      acl.addResource('Admin');
      acl.grant("jim", "Admin", "read");
      acl.allowed("jim", "Admin", "read").should.equal(true);
    });

    it('should disallow access to unknown resources', function() {
      var acl = require('..').createAccessControlList(mockLogger);
      acl.allowed("jim", "Unknown resource", "read").should.equal(false);
    });


    // TODO: functionality not implemented.
    // it('should disallow access to revoked resources', function() {
    //   var acl = require('..').createAccessControlList(mockLogger);
    //   acl.addResource('Admin');
    //   acl.grant("jim", "Admin", "read");
    //   acl.revoke("jim", "Admin", "read");
    //   acl.allowed("jim", "Admin", "read").should.equal(false);
    // });

    // TODO: failing - should it throw error or return false?
    it('should disallow access to undefined resources when others are defined', function() {
      var acl = require('..').createAccessControlList(mockLogger);
      acl.grant("jim", "Admin", "read");
      acl.allowed("jim", "Unknown resource", "read").should.equal(false);
    });

    it('should disallow access to resources granted to users other than the subject', function() {
      var acl = require('..').createAccessControlList(mockLogger);

      acl.addResource('Admin');
      acl.grant("jane", "Admin", "read");
      acl.allowed("jim", "Admin", "read").should.equal(false);
    });
  });
});