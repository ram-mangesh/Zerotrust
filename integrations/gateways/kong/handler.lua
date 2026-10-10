local http = require "resty.http"
local cjson = require "cjson.safe"
local kong = kong

local VajraNetraHandler = {
  PRIORITY = 1000,
  VERSION = "1.0.0",
}

function VajraNetraHandler:access(conf)
  local headers = kong.request.get_headers()
  local path = kong.request.get_path()
  local method = kong.request.get_method()
  local client_ip = kong.client.get_forwarded_ip()

  -- Extract token from Authorization header or cookie
  local token = headers["authorization"]
  if token and token:lower():find("^bearer ") then
    token = token:sub(8)
  else
    local cookie = headers["cookie"]
    if cookie then
      token = cookie:match("ztna_session=([^;]+)")
    end
  end

  if not token then
    local accept = headers["accept"] or ""
    if accept:find("text/html") then
      return kong.response.exit(302, "", {
        ["Location"] = conf.login_url .. "?return_to=" .. kong.request.get_path_with_query(),
      })
    end
    return kong.response.exit(401, {
      error = "unauthenticated",
      detail = "Missing ZTNA token or session cookie",
      login_url = conf.login_url,
    })
  end

  -- Query VajraNetra PDP
  local httpc = http.new()
  httpc:set_timeout(conf.timeout_ms)

  local req_body = cjson.encode({
    token = token,
    client_ip = client_ip,
    path = path,
    method = method,
    min_trust_score = conf.min_trust_score,
  })

  local res, err = httpc:request_uri(conf.pdp_endpoint, {
    method = "POST",
    body = req_body,
    headers = {
      ["Content-Type"] = "application/json",
      ["Accept"] = "application/json",
    },
  })

  if not res then
    kong.log.err("Failed to contact VajraNetra PDP: ", err)
    return kong.response.exit(502, { error = "pdp_unavailable", detail = "VajraNetra authorization service unreachable" })
  end

  if res.status ~= 200 then
    local data = cjson.decode(res.body) or {}
    return kong.response.exit(res.status, data)
  end

  local auth_data = cjson.decode(res.body)
  if not auth_data or not auth_data.allow then
    return kong.response.exit(403, { error = "forbidden", detail = auth_data and auth_data.reason or "Access denied" })
  end

  -- Clear any client-injected spoof headers
  kong.service.request.clear_header("X-Forwarded-User")
  kong.service.request.clear_header("X-Forwarded-Email")
  kong.service.request.clear_header("X-Forwarded-Role")
  kong.service.request.clear_header("X-ZTNA-Trust-Score")
  kong.service.request.clear_header("X-Gateway-Signature")
  kong.service.request.clear_header("X-Gateway-Timestamp")

  -- Inject verified upstream headers
  if auth_data.headers then
    for k, v in pairs(auth_data.headers) do
      kong.service.request.set_header(k, tostring(v))
    end
  end
end

return VajraNetraHandler
