local CustomBasicAuthenticationHandler = {
  VERSION = '1.0.0',
  PRIORITY = -1,
}

local function split(text, delimiter)
  local delimiter_index = string.find(text, delimiter)
  if not delimiter_index then
    return text, nil
  end
  return string.sub(text, 1, delimiter_index - 1), string.sub(text, delimiter_index + 1)
end

local function verify_credentials(config, credentials_base64)
  local credentials = ngx.decode_base64(credentials_base64)
  if not credentials then
    return false
  end

  local username, password = split(credentials, ':')
  return username == config.username
end

local function do_authentication(config, authorization)
  local schema, credentials_base64 = split(authorization, ' ')
  return schema == 'Basic' and verify_credentials(config, credentials_base64)
end

function CustomBasicAuthenticationHandler:access(config)
  local authorization = kong.request.get_header('Authorization')

  if not authorization or not do_authentication(config, authorization) then
    return kong.response.exit(401, 'Unauthorized')
  else
    return
  end
end

CustomBasicAuthenticationHandler.split = split
CustomBasicAuthenticationHandler.verify_credentials = verify_credentials
CustomBasicAuthenticationHandler.do_authentication = do_authentication
return CustomBasicAuthenticationHandler