local BasicAuhtenticationHandler = {
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

local function verify_credentials(base64, conf)
  local credentials = ngx.decode_base64(base64)
  if not credentials then
    return false
  end

  local username, password = split(credentials, ':')
  return username == conf.username and password == conf.password
end

local function do_authentication(conf, authorization)
  local schema, base64 = split(authorization, ' ')
  return schema == 'Basic' and verify_credentials(base64, conf)
end

function BasicAuhtenticationHandler:access(conf)
  local authorization = kong.request.get_header('Authorization')
  if not authorization or not do_authentication(conf, authorization) then
    return kong.response.exit(401, 'Unauthorized')
  end
end

BasicAuhtenticationHandler.split = split
BasicAuhtenticationHandler.verify_credentials = verify_credentials
BasicAuhtenticationHandler.do_authorization = do_authentication
return BasicAuhtenticationHandler
