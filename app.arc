@app
begin-app

@static

@http
get /api/users

@tables
data
  scopeID *String
  dataID **String
  ttl TTL
