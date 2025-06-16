local handler = require 'kong.plugins.basic-authentication.handler'
describe('basic-authentication tests-', function()
  local config = {
    username = 'lnwza',
    password = '1234'
  }

  describe('parse_credentials', function()
    it('should be username and password when credentials have username and password.', function()
      local credentials = 'lnwza:1234'

      local username, password = handler.parse_credentials(credentials)

      assert.is_equal(username, 'lnwza')
      assert.is_equal(password, '1234')
    end)

    it('should be empty and password when credentials have no username.', function()
      local credentials = ':1234'

      local username, password = handler.parse_credentials(credentials)

      assert.is_equal(username, '')
      assert.is_equal(password, '1234')
    end)

    it('should be username and empty when credentials have no password.', function()
      local credentials = 'lnwza:'

      local username, password = handler.parse_credentials(credentials)

      assert.is_equal(username, 'lnwza')
      assert.is_equal(password, '')
    end)

    it('should be empty and empty when credentials have no each username and password.', function()
      local credentials = ':'

      local username, password = handler.parse_credentials(credentials)

      assert.is_equal(username, '')
      assert.is_equal(password, '')
    end)

    it('should be username and null when invalid credentials format.', function()
      local credentials = 'invalid'

      local username, password = handler.parse_credentials(credentials)

      assert.is_equal(username, 'invalid')
      assert.is_equal(password, nil)
    end)
  end)

  describe('decode_credentials_base64', function()
    it('should be username and password when valid base64 format.', function()
      local base_64 = 'bG53emE6MTIzNA=='

      local username, password = handler.decode_credentials_base64(base_64)

      assert.is_equal(username, 'lnwza')
      assert.is_equal(password, '1234')
    end)

    it('should be empty and password when valid base64 format with unknown username.', function()
      local base_64 = 'dW5rbm93bjoxMjM0'

      local username, password = handler.decode_credentials_base64(base_64)

      assert.is_equal(username, 'unknown')
      assert.is_equal(password, '1234')
    end)

    it('should be nil and nil when malform base64.', function()
      local base_64 = 'malformed-base64'

      local username, password = handler.decode_credentials_base64(base_64)

      assert.is_nil(username)
      assert.is_nil(password)
    end)
  end)

  describe('parse_authorization', function()
    it('should be schema and base64 when valid authorization format.', function()
      local authorization = 'Basic bG53emE6MTIzNA=='

      local schema, base64 = handler.parse_authorization(authorization)

      assert.is_equal(schema, 'Basic')
      assert.is_equal(base64, 'bG53emE6MTIzNA==')
    end)

    it('should be schema and base64 when valid authorization format with unknown username.', function()
      local authorization = 'Basic dW5rbm93bjoxMjM0'

      local schema, base64 = handler.parse_authorization(authorization)

      assert.is_equal(schema, 'Basic')
      assert.is_equal(base64, 'dW5rbm93bjoxMjM0')
    end)

    it('should be schema and token when authorization is bearer.', function()
      local authorization = 'Bearer mock-access-token'

      local schema, token = handler.parse_authorization(authorization)

      assert.is_equal(schema, 'Bearer')
      assert.is_equal(token, 'mock-access-token')
    end)

    it('should be schema and nil when invalid authorization format.', function()
      local authorization = 'invalid-format'

      local schema, value = handler.parse_authorization(authorization)

      assert.is_equal(schema, 'invalid-format')
      assert.is_nil(value)
    end)
  end)

  describe('do_authentication', function()
    it('should be true when credentials from authorization matched the configured credentials.', function()
      local authorization = 'Basic bG53emE6MTIzNA=='

      local actual = handler.do_authorization(config, authorization)

      assert.is_true(actual)
    end)

    it('should be false when credentials from authorization not matched the configured credentials.', function()
      local authorization = 'Basic dW5rbm93bjoxMjM0'

      local actual = handler.do_authorization(config, authorization)

      assert.is_false(actual)
    end)

    it('should be false when authorization is bearer.', function()
      local authorization = 'Bearer mock-access-token'

      local actual = handler.do_authorization(config, authorization)

      assert.is_false(actual)
    end)

    it('should be false when valid authorization format but invalid base64.', function()
      local authorization = 'Basic invalid-base64-format'

      local actual = handler.do_authorization(config, authorization)

      assert.is_false(actual)
    end)
  end)

  describe('BasicAuhtenticationHandler:access', function()
    local mock_kong = {}
    _G.kong = mock_kong

    mock_kong.response = {
      exist = function() end
    }
    stub(mock_kong.response, "exit")

    it('should return when credentials request matched the configed credentials.', function()
      mock_kong.request = {
        get_header = function()
          return 'Basic bG53emE6MTIzNA=='
        end
      }

      handler:access(config)

      assert.stub(mock_kong.response.exit).was_not_called()
    end)

    it('should be 401 when credentials request not matched the configed credentials.', function()
      mock_kong.request = {
        get_header = function()
          return 'Basic dW5rbm93bjoxMjM0'
        end
      }

      handler:access(config)

      assert.stub(mock_kong.response.exit).was_called_with(401, "Unauthorized")
    end)

    it('should be 401 when authorization does not exist.', function()
      mock_kong.request = {
        get_header = function()
          return nil
        end
      }

      handler:access(config)

      assert.stub(mock_kong.response.exit).was_called_with(401, "Unauthorized")
    end)
  end)
end)
