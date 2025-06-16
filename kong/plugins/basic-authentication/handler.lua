local BasicAuhtenticationHandler = {
  VERSION = '1.0.0',
  PRIORITY = -1,
}

local function split_once(credentials, delimiter)
  local colon_index = string.find(credentials, delimiter)
  if not colon_index then
    return credentials, nil
  end

  return string.sub(credentials, 1, colon_index - 1), string.sub(credentials, colon_index + 1)
end

local function decode_credentials_base64(base64)
  local credentials = ngx.decode_base64(base64)
  if not credentials then
    return nil, nil
  end

  local username, password = split_once(credentials, ':')
  return username, password
end

local function verify_credentials(base64, conf)
  local username, password = decode_credentials_base64(base64)
  return username == conf.username and password == conf.password
end

local function do_authentication(conf, authorization)
  local schema, base64 = split_once(authorization, ' ')
  return schema == 'Basic' and verify_credentials(base64, conf)
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
BasicAuhtenticationHandler.split_once = split_once
BasicAuhtenticationHandler.verify_credentials = verify_credentials
return BasicAuhtenticationHandler
