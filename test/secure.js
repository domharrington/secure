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

    it('should disallow update access to a resource only read access has been granted to', function() {
      var acl = require('..').createAccessControlList(mockLogger);
      acl.addResource('Admin');
      acl.grant("jim", "Admin", "read");
      acl.allowed("jim", "Admin", "update").should.equal(false);
    });

    it('should allow read access to a resource only update access has been granted to', function() {
      var acl = require('..').createAccessControlList(mockLogger);
      acl.addResource('Admin');
      acl.grant("jim", "Admin", "read");
      acl.allowed("jim", "Admin", "update").should.equal(false);
    });

    it('should allow update access to a resource when * is granted', function() {
      var acl = require('..').createAccessControlList(mockLogger);
      acl.addResource('Admin');
      acl.grant("jim", "Admin", "*");
      acl.allowed("jim", "Admin", "update").should.equal(true);
    });

    // TODO: Failing
    it('should disallow update access to an unknown resources when * is granted to an unrelated resource', function() {
      var acl = require('..').createAccessControlList(mockLogger);
      acl.addResource('Admin');
      acl.grant("jim", "Admin", "*");
      acl.allowed("jim", "Unknown", "update").should.equal(true);
    });

    it('should disallow update access to other resources when * is granted to an unrelated resource', function() {
      var acl = require('..').createAccessControlList(mockLogger);
      acl.addResource('Admin');
      acl.addResource('Other');
      acl.grant("jim", "Admin", "*");
      acl.allowed("jim", "Other", "read").should.equal(false);
    });

    it('should disallow case insensitive operations', function() {
      var acl = require('..').createAccessControlList(mockLogger);
      acl.addResource('Admin');
      acl.grant("jim", "Admin", "*");
      acl.allowed("jim", "admin", "read").should.equal(false);
    });

    // TODO: should or shouldn't it?
    it('should ignore whitespace', function() {
      var acl = require('..').createAccessControlList(mockLogger);
      acl.addResource('Admin ');
      acl.grant("jim", "Admin ", "read");
      acl.allowed("jim", " Admin", "read").should.equal(true);
    });
  });

  describe('#revoke()', function() {
    // TODO: functionality not implemented.
    // it('should disallow access to revoked resources', function() {
    //   var acl = require('..').createAccessControlList(mockLogger);
    //   acl.addResource('Admin');
    //   acl.grant("jim", "Admin", "read");
    //   acl.revoke("jim", "Admin", "read");
    //   acl.allowed("jim", "Admin", "read").should.equal(false);
    // });
  });
});