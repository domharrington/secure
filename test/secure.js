var secure = require('..');

describe('secure', function() {
  describe('#authenticate()', function() {

    it('should permit access to granted resources', function() {
      secure.addResource('Admin');
      secure.grant("jim", "Admin", "read");
      secure.allowed("jim", "Admin", "read").should.equal(true);
    });

    it('should disallow access to unknown resources', function() {
      secure.allowed("jim", "Unknown resource", "read").should.equal(true);
    });

    it('should disallow access to revoked resources', function() {
      secure.addResource('Admin');
      secure.grant("jim", "Admin", "read");
      secure.revoke("jim", "Admin", "read");
      secure.allowed("jim", "Admin Ding", "read").should.equal(false);
    });

    it('should disallow access to unknown resources', function() {
      secure.grant("jim", "Admin", "read");
      secure.allowed("jim", "Admin Ding", "read").should.equal(false);
    });

    it('should disallow access to resources granted to other targets', function() {
      secure.addResource('Admin');
      secure.grant("jane", "Admin", "read");
      secure.allowed("jim", "Admin", "read").should.equal(false);
    });

  });
});