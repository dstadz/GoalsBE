@app
begin-app

@static

@http
get /users

@tables
data
  scopeID *String
  dataID **String
  ttl TTL
