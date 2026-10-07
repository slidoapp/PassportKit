#!/usr/bin/env bash
# End-to-end smoke test: starts the server, exercises each supported flow with curl.
cd "$(dirname "$0")"

PORT="${SMOKE_PORT:-9411}"
ISSUER="http://localhost:$PORT"
WORK="$(mktemp -d)"
failures=0
trap 'kill "$SERVER_PID" 2>/dev/null; rm -rf "$WORK"' EXIT

PORT=$PORT node server.js >"$WORK/server.log" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 50); do curl -sf "$ISSUER/.well-known/openid-configuration" >/dev/null && break; sleep 0.2; done

# json <document> <key>: prints a top-level value (empty when missing), or the raw document for key "."
json() { python3 -c 'import json,sys
d=json.loads(sys.argv[1]); k=sys.argv[2]
v=d.get(k) if k!="." else d
print("" if v is None else (v if isinstance(v,str) else json.dumps(v)))' "$1" "$2" 2>/dev/null; }

# status_and_body <curl args...>: prints "<status>\n<body>" so callers can split the two.
post() { curl -s -w '\n%{http_code}' "$@"; }
body_of() { sed '$d' <<<"$1"; }
code_of() { tail -n1 <<<"$1"; }

check() { # check <description> <expected> <actual>
  if [ "$2" = "$3" ]; then echo "ok   - $1"; else echo "FAIL - $1 (expected '$2', got '$3')"; failures=$((failures+1)); fi
}
check_has() { # check_has <description> <needle> <haystack>
  if [[ "$3" == *"$2"* ]]; then echo "ok   - $1"; else echo "FAIL - $1 (missing '$2' in '$3')"; failures=$((failures+1)); fi
}
check_lacks() {
  if [[ "$3" != *"$2"* ]]; then echo "ok   - $1"; else echo "FAIL - $1 (unexpected '$2' in '$3')"; failures=$((failures+1)); fi
}

token() { post "$ISSUER/token" "$@"; }
V1="https://api.example.com/v1/things"
DENIED="https://api.example.com/denied/vault"

# device_login <scope> <device/auth curl args...>: sets DEVICE_RESPONSE/DEVICE_STATUS from the token response
# (optional DEVICE_TOKEN_EXTRA="resource=..." is added to the token request)
device_login() {
  local scope="$1"; shift
  local started user_code device_code
  started=$(curl -s "$ISSUER/device/auth" -d client_id=public-native --data-urlencode "scope=$scope" "$@")
  user_code=$(json "$started" user_code); device_code=$(json "$started" device_code)
  local pending
  pending=$(token -d grant_type=urn:ietf:params:oauth:grant-type:device_code -d client_id=public-native -d device_code="$device_code")
  check "device: pending before approval" authorization_pending "$(json "$(body_of "$pending")" error)"
  local approval
  approval=$(post -X POST "$ISSUER/test/device/approve" -H 'content-type: application/json' -d "{\"user_code\":\"$user_code\"}")
  check "device: approve endpoint" 200 "$(code_of "$approval")"
  DEVICE_RESPONSE=$(token -d grant_type=urn:ietf:params:oauth:grant-type:device_code -d client_id=public-native -d device_code="$device_code" -d "${DEVICE_TOKEN_EXTRA:-unused=1}")
  DEVICE_STATUS=$(code_of "$DEVICE_RESPONSE"); DEVICE_RESPONSE=$(body_of "$DEVICE_RESPONSE")
}

echo "== metadata"
OIDC=$(curl -s "$ISSUER/.well-known/openid-configuration")
RFC8414=$(curl -s "$ISSUER/.well-known/oauth-authorization-server")
check "metadata: issuer (openid-configuration)" "$ISSUER" "$(json "$OIDC" issuer)"
check "metadata: issuer (RFC 8414 path)" "$ISSUER" "$(json "$RFC8414" issuer)"
check "metadata: iss parameter advertised" True "$(json "$RFC8414" authorization_response_iss_parameter_supported | sed 's/true/True/')"
check "metadata: PKCE S256 only" '["S256"]' "$(json "$RFC8414" code_challenge_methods_supported)"
check_has "metadata: revocation endpoint" /token/revocation "$(json "$RFC8414" revocation_endpoint)"
check_has "metadata: device endpoint" /device/auth "$(json "$RFC8414" device_authorization_endpoint)"
check "metadata: introspection off" "" "$(json "$RFC8414" introspection_endpoint)"

echo "== device flow, refresh rotation, narrowed refresh"
DEVICE_TOKEN_EXTRA="resource=$V1"
device_login "openid offline_access api:read api:write" --data-urlencode "resource=$V1" --data-urlencode "resource=$DENIED"
check "device: token response" 200 "$DEVICE_STATUS"
ACCESS=$(json "$DEVICE_RESPONSE" access_token); REFRESH1=$(json "$DEVICE_RESPONSE" refresh_token)
check_has "device: scope includes api:read" api:read "$(json "$DEVICE_RESPONSE" scope)"
check "device: refresh token issued" yes "$([ -n "$REFRESH1" ] && echo yes)"

R=$(token -d grant_type=refresh_token -d client_id=public-native -d refresh_token="$REFRESH1" --data-urlencode "resource=$DENIED")
check "refresh with /denied/ resource: HTTP 200" 200 "$(code_of "$R")"
check_lacks "refresh with /denied/ resource: scope narrowed" api:read "$(json "$(body_of "$R")" scope)"
REFRESH2=$(json "$(body_of "$R")" refresh_token)
check "refresh: rotated token differs" yes "$([ -n "$REFRESH2" ] && [ "$REFRESH2" != "$REFRESH1" ] && echo yes)"

R=$(token -d grant_type=refresh_token -d client_id=public-native -d refresh_token="$REFRESH2" --data-urlencode "resource=$V1")
check "refresh with normal resource: HTTP 200" 200 "$(code_of "$R")"
check_has "refresh with normal resource: scope kept" api:read "$(json "$(body_of "$R")" scope)"
REFRESH3=$(json "$(body_of "$R")" refresh_token)

R=$(token -d grant_type=refresh_token -d client_id=public-native -d refresh_token="$REFRESH2" --data-urlencode "resource=$V1")
check "refresh: reused token rejected (400)" 400 "$(code_of "$R")"
check "refresh: reused token invalid_grant" invalid_grant "$(json "$(body_of "$R")" error)"
R=$(token -d grant_type=refresh_token -d client_id=public-native -d refresh_token="$REFRESH3" --data-urlencode "resource=$V1")
check "refresh: reuse revokes the whole grant" invalid_grant "$(json "$(body_of "$R")" error)"

echo "== device deny"
started=$(curl -s "$ISSUER/device/auth" -d client_id=public-native -d scope=openid)
approval=$(post -X POST "$ISSUER/test/device/deny" -H 'content-type: application/json' -d "{\"user_code\":\"$(json "$started" user_code)\"}")
R=$(token -d grant_type=urn:ietf:params:oauth:grant-type:device_code -d client_id=public-native -d device_code="$(json "$started" device_code)")
check "device deny: access_denied" access_denied "$(json "$(body_of "$R")" error)"

echo "== token exchange"
DEVICE_TOKEN_EXTRA="resource=$V1"
device_login "openid offline_access api:read api:write" --data-urlencode "resource=$V1"
ACCESS=$(json "$DEVICE_RESPONSE" access_token); REFRESH=$(json "$DEVICE_RESPONSE" refresh_token)
EXCHANGE="urn:ietf:params:oauth:grant-type:token-exchange"
AT_TYPE="urn:ietf:params:oauth:token-type:access_token"; RT_TYPE="urn:ietf:params:oauth:token-type:refresh_token"
R=$(token -d grant_type=$EXCHANGE -d client_id=public-native -d subject_token="$ACCESS" -d subject_token_type=$AT_TYPE --data-urlencode "resource=https://api.example.com/v2/other")
check "exchange access token: HTTP 200" 200 "$(code_of "$R")"
check "exchange access token: issued_token_type" $AT_TYPE "$(json "$(body_of "$R")" issued_token_type)"
check_has "exchange access token: scope" api:read "$(json "$(body_of "$R")" scope)"
R=$(token -d grant_type=$EXCHANGE -d client_id=public-native -d subject_token="$ACCESS" -d subject_token_type=$AT_TYPE --data-urlencode "resource=$DENIED")
check "exchange denied resource: HTTP 401" 401 "$(code_of "$R")"
check "exchange denied resource: access_denied" access_denied "$(json "$(body_of "$R")" error)"
R=$(token -d grant_type=$EXCHANGE -d client_id=public-native -d subject_token=bogus -d subject_token_type=$AT_TYPE --data-urlencode "resource=$V1")
check "exchange bogus subject: invalid_grant" invalid_grant "$(json "$(body_of "$R")" error)"

R=$(token -d grant_type=$EXCHANGE -d client_id=public-native -d subject_token="$REFRESH" -d subject_token_type=$RT_TYPE -d audience=audience-client)
check "exchange refresh token: HTTP 200" 200 "$(code_of "$R")"
B=$(body_of "$R")
check "exchange refresh token: issued_token_type" $RT_TYPE "$(json "$B" issued_token_type)"
AUDIENCE_RT=$(json "$B" access_token); ROTATED=$(json "$B" refresh_token)
check "exchange refresh token: subject rotated" yes "$([ -n "$ROTATED" ] && [ "$ROTATED" != "$REFRESH" ] && echo yes)"
R=$(token -d grant_type=refresh_token -d client_id=audience-client -d refresh_token="$AUDIENCE_RT")
check "audience client can use issued refresh token" 200 "$(code_of "$R")"
R=$(token -d grant_type=refresh_token -d client_id=public-native -d refresh_token="$ROTATED" --data-urlencode "resource=$V1")
check "rotated subject refresh token still works" 200 "$(code_of "$R")"
REFRESH_LIVE=$(json "$(body_of "$R")" refresh_token); ACCESS_LIVE=$(json "$(body_of "$R")" access_token)
R=$(token -d grant_type=$EXCHANGE -d client_id=public-native -d subject_token="$REFRESH" -d subject_token_type=$RT_TYPE -d audience=audience-client)
check "exchange: consumed subject refresh token rejected" invalid_grant "$(json "$(body_of "$R")" error)"

echo "== client credentials"
R=$(token -u confidential-service:integration-secret -d grant_type=client_credentials -d scope=api:read --data-urlencode "resource=$V1")
check "client credentials (basic): HTTP 200" 200 "$(code_of "$R")"
check "client credentials (basic): scope" api:read "$(json "$(body_of "$R")" scope)"
R=$(token -d client_id=confidential-service -d client_secret=integration-secret -d grant_type=client_credentials -d scope=api:read --data-urlencode "resource=$V1")
check "client credentials (post): HTTP 200" 200 "$(code_of "$R")"
R=$(token -u confidential-service:wrong -d grant_type=client_credentials)
check "client credentials: wrong secret rejected" invalid_client "$(json "$(body_of "$R")" error)"
R=$(token -u confidential-service:integration-secret -d grant_type=client_credentials --data-urlencode "resource=https://other.example.org/x")
check "client credentials: foreign resource rejected" invalid_target "$(json "$(body_of "$R")" error)"

echo "== revocation"
DEVICE_TOKEN_EXTRA="resource=$V1"
device_login "openid offline_access api:read" --data-urlencode "resource=$V1"
ACCESS=$(json "$DEVICE_RESPONSE" access_token); REFRESH=$(json "$DEVICE_RESPONSE" refresh_token)
R=$(post "$ISSUER/token/revocation" -d client_id=public-native -d token="$ACCESS")
check "revoke access token: HTTP 200" 200 "$(code_of "$R")"
R=$(post "$ISSUER/token/revocation" -d client_id=public-native -d token="$REFRESH")
check "revoke refresh token: HTTP 200" 200 "$(code_of "$R")"
R=$(token -d grant_type=refresh_token -d client_id=public-native -d refresh_token="$REFRESH" --data-urlencode "resource=$V1")
check "revoked refresh token rejected" invalid_grant "$(json "$(body_of "$R")" error)"
R=$(post "$ISSUER/token/introspection" -u confidential-service:integration-secret -d token="$ACCESS")
check "introspection disabled (404)" 404 "$(code_of "$R")"

echo "== authorization code + PKCE (auto interaction)"
VERIFIER=$(python3 -c 'import secrets;print(secrets.token_urlsafe(48))')
CHALLENGE=$(python3 -c 'import sys,hashlib,base64;print(base64.urlsafe_b64encode(hashlib.sha256(sys.argv[1].encode()).digest()).rstrip(b"=").decode())' "$VERIFIER")
REDIRECT="http://127.0.0.1:53211/callback"

# authorize <extra query>: follows redirects with curl until the loopback redirect; prints that Location.
authorize() {
  local url="$ISSUER/auth?client_id=public-native&response_type=code&scope=openid%20offline_access%20api:read&prompt=consent&state=xyz&redirect_uri=$REDIRECT&resource=$V1&$1"
  : >"$WORK/jar"
  for _ in $(seq 1 15); do
    local headers location
    headers=$(curl -s -D - -o /dev/null -b "$WORK/jar" -c "$WORK/jar" "$url")
    location=$(grep -i '^location:' <<<"$headers" | head -1 | cut -d' ' -f2- | tr -d '\r')
    [ -z "$location" ] && { echo "NO_REDIRECT"; return; }
    case "$location" in "$REDIRECT"*|com.example.app:*) echo "$location"; return;; esac
    case "$location" in /*) url="$ISSUER$location";; *) url="$location";; esac
  done
  echo "TOO_MANY_REDIRECTS"
}
query_param() { python3 -c 'import sys,urllib.parse as u;print(u.parse_qs(u.urlparse(sys.argv[1]).query).get(sys.argv[2],[""])[0])' "$1" "$2"; }

LOCATION=$(authorize "code_challenge=$CHALLENGE&code_challenge_method=S256")
CODE=$(query_param "$LOCATION" code)
check "auth code: redirected to loopback with code" yes "$([ -n "$CODE" ] && echo yes)"
check "auth code: state echoed" xyz "$(query_param "$LOCATION" state)"
check "auth code: RFC 9207 iss parameter" "$ISSUER" "$(query_param "$LOCATION" iss)"
R=$(token -d grant_type=authorization_code -d client_id=public-native -d code="$CODE" --data-urlencode "redirect_uri=$REDIRECT" -d code_verifier="$VERIFIER")
check "auth code: token exchange HTTP 200" 200 "$(code_of "$R")"
check "auth code: refresh token issued" yes "$([ -n "$(json "$(body_of "$R")" refresh_token)" ] && echo yes)"
check_has "auth code: resource scope granted" api:read "$(json "$(body_of "$R")" scope)"
R=$(token -d grant_type=authorization_code -d client_id=public-native -d code="$CODE" --data-urlencode "redirect_uri=$REDIRECT" -d code_verifier="$VERIFIER")
check "auth code: replay rejected" invalid_grant "$(json "$(body_of "$R")" error)"

LOCATION=$(authorize "code_challenge=$CHALLENGE&code_challenge_method=S256")
CODE=$(query_param "$LOCATION" code)
R=$(token -d grant_type=authorization_code -d client_id=public-native -d code="$CODE" --data-urlencode "redirect_uri=$REDIRECT" -d code_verifier="wrong-verifier-wrong-verifier-wrong-verifier-wrong")
check "auth code: wrong verifier rejected" invalid_grant "$(json "$(body_of "$R")" error)"

LOCATION=$(authorize "")
check "auth code: missing PKCE rejected" invalid_request "$(query_param "$LOCATION" error)"
LOCATION=$(authorize "code_challenge=$CHALLENGE&code_challenge_method=plain")
check "auth code: plain method rejected" invalid_request "$(query_param "$LOCATION" error)"

echo
if [ "$failures" -eq 0 ]; then echo "ALL PASSED"; else echo "$failures FAILED (server log: $WORK/server.log)"; trap 'kill "$SERVER_PID" 2>/dev/null' EXIT; fi
exit "$failures"
