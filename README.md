# Jitsi OpenID

Jitsi OpenID is an authentication adapter to provide [jitsi](https://jitsi.org/) the ability to use single sign on
via [OpenID Connect](https://openid.net/connect/).

This repository is a maintained fork of the original
[MarcelCoding/jitsi-openid](https://github.com/MarcelCoding/jitsi-openid) project, which was archived upstream.
The goal of this fork is to keep the adapter maintained with dependency updates, compatibility fixes, and security
hardening.

## Deployment

**This guide is based of the [docker setup from jitsi](https://github.com/jitsi/docker-jitsi-meet/).**

The maintained Docker image is:

```
badsmoke/jitsi-openid:latest
```

### Docker "run" Command

```bash
docker run \
  -p 3000:3000 \
  -e JITSI_SECRET=SECURE_SECRET \
  -e JITSI_URL=https://meet.example.com \
  -e JITSI_SUB=meet.example.com \
  -e ISSUER_URL=https://id.example.com \
  -e BASE_URL=https://auth.meet.example.com \
  -e CLIENT_ID=meet.example.com \
  -e CLIENT_SECRET=SECURE_SECRET \
  --rm \
  badsmoke/jitsi-openid:latest
```

### Docker Compose

```yaml
# docker-compose.yaml

# ...

services:
  # ...

  jitsi-openid:
    image: badsmoke/jitsi-openid:latest
    restart: always
    environment:
      - "JITSI_SECRET=SECURE_SECRET" # <- shared with jitsi (JWT_APP_SECRET -> see .env from jitsi),
      #    secret to sign jwt tokens
      - "JITSI_URL=https://meet.example.com" # <- external url of jitsi
      - "JITSI_SUB=meet.example.com" # <- shared with jitsi (JWT_APP_ID -> see .env from jitsi),
      #    id of jitsi
      - "ISSUER_URL=https://id.example.com" # <- base URL of your OpenID Connect provider
      #    Keycloak: https://id.example.com/auth/realms/<realm>
      - "BASE_URL=https://auth.meet.example.com" # <- base URL of this application
      - "CLIENT_ID=meet.example.com" # <- OpenID Connect Client ID
      - "CLIENT_SECRET=SECURE_SECRET" # <- OpenID Connect Client secret
        # - 'ACR_VALUES=password email'              # <- OpenID Context Authentication Context Requirements,
        #    space separated list of allowed actions (OPTIONAL), see
        #    https://github.com/MarcelCoding/jitsi-openid/issues/122
        # - 'SCOPES=openid email jitsi'              # <- OpenID Scopes, space separated list of scopes (OPTIONAL),
        #    default: openid email
        # - 'VERIFY_ACCESS_TOKEN_HASH=false          # <- explicitly disable access token hash verification (OPTIONAL),
        #    default: true                                See https://github.com/MarcelCoding/jitsi-openid/issues/372#issuecomment-2730510228
        # - 'SKIP_PREJOIN_SCREEN=false'              # <- skips the jitsi prejoin screen after login (default: true)
        # - 'GROUP=example'                          # <- Value for the 'group' field in the token
        #    default: ''
        # - 'JWT_MAX_AGE_SECONDS=300'                # <- Lifetime of generated Jitsi JWTs
        # - 'SESSION_MAX_AGE_SECONDS=1800'           # <- Session lifetime before callback must finish
        # - 'HTTP_TIMEOUT_SECONDS=15'                # <- Total timeout for IDP HTTP requests
        # - 'HTTP_CONNECT_TIMEOUT_SECONDS=5'         # <- Connect timeout for IDP HTTP requests
        # - 'TRUSTED_ID_TOKEN_AUDIENCES=api other'   # <- Additional trusted ID token audiences
        #    default: reject additional audiences
        # - 'CA_CERTIFICATE_FILE=/certs/root-ca.pem' # <- Optional extra PEM CA certificate for private IDPs
        # - 'CA_CERTIFICATE_FILES=/certs/a.pem /certs/b.pem'
        #    Optional space separated PEM CA certificate files
    ports:
      - "3000:3000"
# ...
```

To generate the `JITSI_SECRET` you can use one of the following command:

```bash
cat /dev/urandom | tr -dc a-zA-Z0-9 | head -c128; echo
```

### Jitsi Configuration

If you have problems understating this have a look here: https://github.com/MarcelCoding/jitsi-openid/issues/80

```bash
# for more information see:
# https://github.com/jitsi/docker-jitsi-meet/blob/master/env.example

# weather to allow users to join a room without requiring to authenticate
#ENABLE_GUESTS=1

# fixed
ENABLE_AUTH=1
AUTH_TYPE=jwt

# should be the same as JITSI_ID of jitsi-openid environment variables
JWT_APP_ID=meet.example.com
# should be the same as JITSI_SECRET of jitsi-openid environment variables
JWT_APP_SECRET=SECRET

# fixed values
JWT_ACCEPTED_ISSUERS=jitsi
JWT_ACCEPTED_AUDIENCES=jitsi

# auth.meet.example.com should be the domain name of jitsi-openid,
# `/room/{room}` is the endpoint that's jitsi redirecting the user to
# `{room}` is is a placeholder, where jitsi inserts the room name
# jitsi-openid should redirect the user after a successfully authentication
# !! it is recommend to use ALWAYS https e.g. using a reverse proxy !!
TOKEN_AUTH_URL=https://auth.meet.example.com/room/{room}
```

### Jitsi JWTs

The JWTs are populated using the data returned by your IDP.
This includes the user id, email and name.

The user id is extracted from the OpenID Connect `sub` claim.

The generated Jitsi JWT is scoped to the requested room and expires after `JWT_MAX_AGE_SECONDS`.
The default lifetime is 300 seconds.

The `name` is extracted from the `name` field, if that isn't preset a concatenation of `given_name`, `middle_name`
and `family_name` is used. If all tree of them are also not present the `prefered_username` is used.

The `affiliation` is straight up passed, without any modifications or alternatives. It can be used to restrict the
permissions a user has in a specific room in jitsi.
See https://github.com/jitsi-contrib/prosody-plugins/tree/main/token_affiliation for more information.

The picture (avatar) URL is delegated from the IDP to Jitsi.

Translations aren't respected: https://github.com/MarcelCoding/jitsi-openid/issues/117#issuecomment-1172406703

### Security Notes

Room names are appended to `JITSI_URL` as encoded path segments, so URL-like room names cannot redirect users away from
the configured Jitsi host.

ID tokens must contain this application's client id as an audience. Additional audiences are rejected unless they are
listed in `TRUSTED_ID_TOKEN_AUDIENCES`.

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## Contact

For issues or contributions, open an issue in the repository or reach out via email.

github@badcloud.eu

## License

This fork remains licensed under the GNU Affero General Public License v3.0, matching the original project.

[LICENSE](LICENSE)
