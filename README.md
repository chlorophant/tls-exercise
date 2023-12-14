
# Golang Reverse Proxy Exercise

### Problem Prompt:

Create a microservice in Go that serves a TLS endpoint using a dynamically generated server certificate signed by an intermediate CA using the request URI. Cache the dynamically generated certificate in memory for future use. Write as much of it as possible using native golang modules. This is a reverse proxy use case, so the request URI is not a fixed value, but instead could be anything. The server cert should be signed by an intermediate CA, which was signed by a root CA. It doesn't have to be a public root CA that signs the intermediate. 



### Approach:

1. Create a root CA certificate when the service starts
2. Create an intermediate CA certificate signed by the root cert when the service starts
3. Create an endpoint "/" which always responds 200 OK and communicates on https/443
    * It is likely required for the endpoint to initially be http, and then be upgraded after the uri is known (to create or fetch the needed cert)
4. For each unique requested URI, which would be a subroute of "/", create a dynamic cert which is signed by the intermediate CA (example: "/foo?bar=baz" would have a different cert than "/foo?baz=bar")
5. For demo purposes, consider returning the entire certificate chain


### Attempts
1. Cannot change out the cert on the fly unless using GetCertificate on the tls config, which does not have access to the URI (only has access to SNI servername aka host aka "localhost")
2. Using HTTP to create/cache a cert, then redirecting the connection has the same pitfall
3. Perhaps a new tls server should be created (with the relevant cert) for each URI requested (using http) and then be redirected/upgraded to it (this seems wasteful!)
4. Hint from the prompter: Look into the tls handshake
    - As far as I can tell, its the same roadblock as it only has access to the SNI servername aka host aka "localhost"


### Useful Resources:
* See: https://pkg.go.dev/crypto/x509#Certificate
* See: https://go.dev/src/crypto/tls/handshake_server.go
* See: https://shaneutt.com/blog/golang-ca-and-signed-cert-go/
* See: https://gist.github.com/Mattemagikern/328cdd650be33bc33105e26db88e487d
* See: https://www.statuscake.com/blog/serving-multiple-ssl-certificates-in-your-go-tests/
* See: https://opensource.com/article/22/9/dynamically-update-tls-certificates-golang-server-no-downtime
* Watch: https://www.youtube.com/watch?v=kAaIYRJoJkc
* Watch: https://www.youtube.com/watch?v=86cQJ0MMses
* Thread on why this might not be possible: https://security.stackexchange.com/questions/215383/does-tls-have-any-way-of-exposing-only-the-uri-in-a-ssl-ssl-proxy-or-bluecoat-s
