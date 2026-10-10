local typedefs = require "kong.db.schema.typedefs"

return {
  name = "vajranetra-ztna",
  fields = {
    { consumer = typedefs.no_consumer },
    { protocols = typedefs.protocols_http },
    {
      config = {
        type = "record",
        fields = {
          {
            pdp_endpoint = {
              type = "string",
              default = "http://vajranetra-backend:8000/api/gateways/kong/verify",
              required = true,
            },
          },
          {
            min_trust_score = {
              type = "number",
              default = 30.0,
              between = { 0, 100 },
            },
          },
          {
            timeout_ms = {
              type = "number",
              default = 2000,
            },
          },
          {
            login_url = {
              type = "string",
              default = "http://vajranetra-backend:8000/__ztna/login",
            },
          },
        },
      },
    },
  },
}
