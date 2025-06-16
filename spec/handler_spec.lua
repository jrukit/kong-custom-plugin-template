local handler = require 'kong.plugins.basic-authentication.handler'
describe('basic-authentication tests-', function()
  local config = {
    username = 'lnwza',
    password = '1234'
  }

  describe('split_once', function()
    it('should be pair value when delimiter is colon.', function()
      local first, second = handler.split_once('lnwza:1234', ':')

      assert.is_equal(first, 'lnwza')
      assert.is_equal(second, '1234')
    end)

    it('should be empty and second value when empty string before colon.', function()
      local first, second = handler.split_once(':1234', ':')

      assert.is_equal(first, '')
      assert.is_equal(second, '1234')
    end)

    it('should be first value and empty value when empty string after colon.', function()
      local credentials = 'lnwza:'

      local first, second = handler.split_once('lnwza:', ':')

      assert.is_equal(first, 'lnwza')
      assert.is_equal(second, '')
    end)

    it('should be empty and empty when empty between colon.', function()
      local first, second = handler.split_once(':', ':')

      assert.is_equal(first, '')
      assert.is_equal(second, '')
    end)

    it('should be pair value when delimiter is space.', function()
      local first, second = handler.split_once('Basic bG53emE6MTIzNA==', ' ')

      assert.is_equal(first, 'Basic')
      assert.is_equal(second, 'bG53emE6MTIzNA==')
    end)

    it('should be empty and second value when empty before space.', function()
      local first, second = handler.split_once(' bG53emE6MTIzNA==', ' ')

      assert.is_equal(first, '')
      assert.is_equal(second, 'bG53emE6MTIzNA==')
    end)

    it('should be first value and empty value when empty after space.', function()
      local first, second = handler.split_once(' ', ' ')

      assert.is_equal(first, '')
      assert.is_equal(second, '')
    end)

    it('should be empty and empty value when empty between space.', function()
      local first, second = handler.split_once('Basic ', ' ')

      assert.is_equal(first, 'Basic')
      assert.is_equal(second, '')
    end)

    it('should be first and null when invalid format.', function()
      local credentials = 'invalid'

      local first, second = handler.split_once('invalid', ':')

      assert.is_equal(first, 'invalid')
      assert.is_equal(second, nil)
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

  describe('verify_credentials', function()
    it('should be true when credentials base64 matched the configured credentials', function()
      local base64 = 'bG53emE6MTIzNA=='

      local actual = handler.verify_credentials(base64, config)

      assert.is_true(actual)
    end)

    it('should be false when username base64 not matched the configured credentials', function()
      local base64 = 'dW5rbm93bjoxMjM0'

      local actual = handler.verify_credentials(base64, config)

      assert.is_false(actual)
    end)

    it('should be false when password base64 not matched the configured credentials', function()
      local base64 = 'bG53emE6MTIzNDU='

      local actual = handler.verify_credentials(base64, config)

      assert.is_false(actual)
    end)

    it('should be false when malformed base64 not matched the configured credentials', function()
      local base64 = 'malformed'

      local actual = handler.verify_credentials(base64, config)

      assert.is_false(actual)
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
