local BasicAuhtenticationHandler = {
  VERSION = '1.0.0',
  PRIORITY = -1,
}

local function parse_credentials(credentials)
  local colon_index = string.find(credentials, ':')
  if not colon_index then
    return credentials, nil
  end
  return string.sub(credentials, 1, colon_index - 1), string.sub(credentials, colon_index + 1)
end

local function parse_authorization(authorization)
  local space_index = string.find(authorization, ' ')
  if not space_index then
    return authorization, nil
  end
  return string.sub(authorization, 1, space_index - 1), string.sub(authorization, space_index + 1)
end

local function decode_credentials_base64(base64)
  local credentials = ngx.decode_base64(base64)
  if not credentials then
    return nil, nil
  end

  local username, password = parse_credentials(credentials)
  return username, password
end

local function do_authentication(conf, authorization)
  local schema, base64 = parse_authorization(authorization)
  if schema ~= 'Basic' then
    return false
  end

  local username, password = decode_credentials_base64(base64)
  return username == conf.username and password == conf.password
end

function BasicAuhtenticationHandler:access(conf)
  local authorization = kong.request.get_header('Authorization')
  if not authorization or not do_authentication(conf, authorization) then
    return kong.response.exit(401, 'Unauthorized')
  end
end

BasicAuhtenticationHandler.do_authorization = do_authentication
BasicAuhtenticationHandler.parse_authorization = parse_authorization
BasicAuhtenticationHandler.decode_credentials_base64 = decode_credentials_base64
BasicAuhtenticationHandler.parse_credentials = parse_credentials
return BasicAuhtenticationHandler
