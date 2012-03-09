var secure = require('..');

describe('secure', function() {
  describe('#authenticate()', function() {

    it('should permit access to granted resources', function() {
      secure.addResource('Admin');
      secure.addResource('Admin Bar');
    });

    it('should disallow access to unspecified resources', function() {

    });

    it('should disallow access to revoked resources', function() {

    });

  });
});