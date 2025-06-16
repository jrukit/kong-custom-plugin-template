local handler = require 'kong.plugins.basic-authorization.handler'
describe("basic-authorization tests-", function()
  describe("BasicAuhtorizationHandler:access", function()
    it("test", function()
      handler:access()
      assert.is_true(true)
    end)
  end)
end)