local handler = require 'kong.plugins.custom-basic-authentication.handler'
describe('custom-basic-authentication tests -', function()
  local config = {
    username = 'lnwza007',
    password = '1234'
  }

  local mock_kong = {}
  _G.kong = mock_kong

  mock_kong.response = {
    exit = function() end
  }
  stub(mock_kong.response, "exit")

  describe('split', function()
    it('should be first value and second value when values between colon.', function()
      local first, second = handler.split('first-value:second-value', ':')

      assert.is_equal('first-value', first)
      assert.is_equal('second-value', second)
    end)

    it('should be first value and second value when values between space.', function()
      local first, second = handler.split('first-value01 second-value01', ' ')

      assert.is_equal('first-value01', first)
      assert.is_equal('second-value01', second)
    end)

    it('should be empty and second value when colon after empty.', function()
      local first, second = handler.split(':second', ':')

      assert.is_equal('', first)
      assert.is_equal('second', second)
    end)

    it('should be first value and empty when colon before empty.', function()
      local first, second = handler.split('first:', ':')

      assert.is_equal('first', first)
      assert.is_equal('', second)
    end)

    it('should be both empty when space between both empty.', function()
      local first, second = handler.split(' ', ' ')

      assert.is_equal('', first)
      assert.is_equal('', second)
    end)

    it('should be first value and nil when invalid format.', function()
      local first, second = handler.split('invalid-format', ':')

      assert.is_equal('invalid-format', first)
      assert.is_nil(second)
    end)
  end)

  describe('verify_credentials', function()
    it('should be true when client credentials is matched.', function()
      local credentials_base64 = 'bG53emEwMDc6MTIzNA=='

      local actual = handler.verify_credentials(config, credentials_base64)

      assert.is_true(actual)
    end)

    it('should be false when client username is not matched.', function()
      local credentials_base64 = 'dW5rbm93bjoxMjM0'

      local actual = handler.verify_credentials(config, credentials_base64)

      assert.is_false(actual)
    end)

    it('should be false when client password is not matched.', function()
      local credentials_base64 = 'bG53emEwMDc6MTIzNDU='

      local actual = handler.verify_credentials(config, credentials_base64)

      assert.is_false(actual)
    end)
    
    it('should be false when credentials base64 malformed.', function()
      local credentials_base64 = 'malformed'

      local actual = handler.verify_credentials(config, credentials_base64)

      assert.is_false(actual)
    end)
  end)

  describe('do_authentication', function()
    it('should be true when authorization uses basic schema and the credentials are matched.', function()
      local authorization = 'Basic bG53emEwMDc6MTIzNA=='

      local actual = handler.do_authentication(config, authorization)

      assert.is_true(actual)
    end)

    it('should be false when authorization uses basic schema but the credentials are not matched.', function()
      local authorization = 'Basic dW5rbm93bjoxMjM0'

      local actual = handler.do_authentication(config, authorization)

      assert.is_false(actual)
    end)

    it('should be false when authorization uses basic schema but the credentials malformed.', function()
      local authorization = 'Basic malformed'

      local actual = handler.do_authentication(config, authorization)

      assert.is_false(actual)
    end)

    it('should be false when authorization uses bearer.', function()
      local authorization = 'Bearer mock-access-token'

      local actual = handler.do_authentication(config, authorization)

      assert.is_false(actual)
    end)
  end)

  describe('CustomBasicAuthenticationHandler:access', function()
    it('should pass through when the client credentials match the configured credentials.', function()
      -- given
      mock_kong.request = {
        get_header = function()
          return 'Basic bG53emEwMDc6MTIzNA=='
        end
      }

      -- when
      handler:access(config)

      -- then
      assert.stub(mock_kong.response.exit).was_not_called()
    end)

    it('should be 401 Unauthorized when the client credentials not match the configured credentials.', function()
      -- given
      mock_kong.request = {
        get_header = function()
          return 'Basic dW5rbm93bjoxMjM0'
        end
      }

      -- when
      handler:access(config)

      -- then
      assert.stub(mock_kong.response.exit).was_called.with(401, 'Unauthorized')
    end)

    it('should be 401 Unauthorized when the authorization header does not exist.', function()
      -- given
      mock_kong.request = {
        get_header = function()
          return nil
        end
      }

      -- when
      handler:access(config)

      -- then
      assert.stub(mock_kong.response.exit).was_called.with(401, 'Unauthorized')
    end)
  end)
end)