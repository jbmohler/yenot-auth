# Introduction

This builds on the yenot server framework with an authentication framework and
a basic declarative data structure for describing an end-point to the client.

# Permissions & Roles

Provides role add/remove and end-points to assign users to roles and end-points
to roles.  In this way, users can be assigned to 1 or more roles and gain
access to related groups of end-points.

# Declarative structure for Reports (aka end-points)

Yenot end-points can be annotated with `report_prompts` and `report_sidebars`
which describe to a client what kind of input widgets to use in a generic
reporting client.  The sidebars describe to the client what related data a user
may want to see when looking at a report.

Idealistic dreams aside, this basically provides a language on which a client
application and Yenot extension server can use to agree on inputs and
structured views of output.

# Tokens & Authentication

Provides a user add/remove and authentication end-point.  Individual requests
are authenticated with a bearer token.  Device tokens are currently supported
and rotating refresh tokens are likely coming soon.

Provision JWT claims to be implemented.

|                  | access       | refresh                 | device                  | 2fa-verify     |
|------------------|--------------|-------------------------|-------------------------|----------------|
| iss              | ????         | ???                     | ???                     | ???            |
| sub              | userid       | userid                  | userid                  | userid         |
| aud              | https://.../ | https://.../api/session | https://.../api/session | ????           |
| exp              | 60 minutes   | 60 minutes              | 60 days (flexible)      | 10 minutes     |
| nbf              | 0            | 0                       | 0                       | 0              |
| iat              | 0            | 0                       | 0                       | 0              |
| yenot-session-id | session id   | session id              |                         | session-id     |
| yenot-refresh-id |              | refresh id              |                         |                |
| yenot-device-id  |              |                         | device auth id          |                |
| yenot-type       | access       | refresh                 | device                  | 2fa-verify     |

# Philosophy and Literature

It is the position of the author of this yenot-auth library that JWT's can be
appropriately used with sessions.  One may interpret this to mean that a JWT by
itself is not a bearer token -- that is, the act of bearing the token does not
by itself grant authentication but the session must also exist in the database.
The value that this delivers is that an access token proves it's own timely use
independent of the session expiration on the server.  Session expirations can
be extended, but the access token is insufficient to do so.  Only requests with
non-expired (and valid) refresh tokens can extend the session expiration.
Therefore breaches that gain access tokens are only useful to a malicious actor
for a brief period even though the session itself is long lived.

The articles below informed this thinking.

- https://stackoverflow.com/questions/39228465/how-to-decode-jwt-token-payload-on-client-side
- https://github.com/expressjs/session
- https://pragmaticwebsecurity.com/articles/oauthoidc/refresh-token-protection-implications.html
- https://auth0.com/blog/refresh-tokens-what-are-they-and-when-to-use-them/
- http://cryto.net/~joepie91/blog/2016/06/13/stop-using-jwt-for-sessions/

# Process Isolation

It is recommended that the endpoints prefixed by /api/session be handled by
a process separate from the main application.

# Test Suite

From a bare linux system it is easiest to run the test suite against a docker
installed postgres.  This very short pointer does not include docker
installation.  Note that after the closing `docker stop` command the postgres
testing instance is completely gone.  Specific db hosting methods are beyond
the scope of this README.

This test suite references a yenot repo clone as well presumably in a sibling
directory to yenot-auth.  This location is indicated with the YENOT_REPO
environment variable as set below.

```
docker run --rm --name yenot-test-postgres -e POSTGRES_PASSWORD=mysecretpassword -p 5432:5432 -d postgres
sleep 6
# optionally check the PG version
docker exec yenot-test-postgres psql -U postgres -h localhost -c "select version()"
docker exec yenot-test-postgres createdb -U postgres -h localhost my_coverage_test
YENOT_DEBUG=debug YENOT_REPO=../yenot YENOT_DB_URL=postgresql://postgres:mysecretpassword@localhost/my_coverage_test YENOT_AUTH_SIGNING_SECRET=asdfg123456 sh full-coverage.sh
# consider dropping the database before re-running the full-coverage test scripts
docker exec yenot-test-postgres dropdb -U postgres -h localhost my_coverage_test
docker stop yenot-test-postgres
```
