local handler = require 'kong.plugins.my-plugin.handler'
describe("my plugin tests-", function()
  describe("MyPluginHandler:access", function()
    it("test", function()
      handler:access()
      assert.is_true(true)
    end)
  end)
end)