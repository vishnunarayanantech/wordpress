#!/usr/bin/env bash
#
# Black-box HTTP checks for WP Security Lockdown, using only curl.
#
# Run it against a DISPOSABLE copy of a site on which the plugin is ACTIVE with the default policy.
# It never creates content: every state-changing request below is one the plugin must refuse.
# The optional lockout test (WPSL_LOCKOUT=1) deliberately locks the address you run it from for the
# configured lockout time (default 15 minutes).
#
# Usage:
#   WPSL_BASE=http://127.0.0.1:8099 \
#   WPSL_ADMIN_USER=admin WPSL_ADMIN_PASS=... \
#   WPSL_SUB_USER=subscriber WPSL_SUB_PASS=... \
#   bash tests/http-smoke.sh
#
# Optional: WPSL_POST_ID (a published post, default 1), WPSL_AUTHOR_ID (an author with published posts,
# default 1), WPSL_LOCKOUT=1, WPSL_REWRITE=1 (the site has pretty permalink rewriting, enables sitemap checks).
# Exit status = number of failed checks.

set -u
BASE="${WPSL_BASE:?set WPSL_BASE, e.g. http://127.0.0.1:8099}"
BASE="${BASE%/}"
POST_ID="${WPSL_POST_ID:-1}"
AUTHOR_ID="${WPSL_AUTHOR_ID:-1}"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
pass=0; fail=0

check() { # name actual expected-regex
	if [[ "$2" =~ $3 ]]; then printf 'PASS  %s\n' "$1"; pass=$((pass + 1)); else printf 'FAIL  %s  (got: %s, expected: %s)\n' "$1" "$2" "$3"; fail=$((fail + 1)); fi
}
code() { curl -s -o /dev/null -m 20 -w '%{http_code}' "$@"; }
body() { curl -s -m 20 "$@"; }

echo "== XML-RPC: must be rejected, not merely hidden =="
LIST='<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params/></methodCall>'
PING='<?xml version="1.0"?><methodCall><methodName>pingback.ping</methodName><params><param><value><string>http://127.0.0.1:9/x</string></value></param><param><value><string>'"$BASE"'/?p='"$POST_ID"'</string></value></param></params></methodCall>'
check "system.listMethods answers 403"        "$(code -H 'Content-Type: text/xml' --data "$LIST" "$BASE/xmlrpc.php")" '^403$'
check "pingback.ping (unauthenticated) 403"   "$(code -H 'Content-Type: text/xml' --data "$PING" "$BASE/xmlrpc.php")" '^403$'
check "no XML-RPC response body"              "$(body -H 'Content-Type: text/xml' --data "$LIST" "$BASE/xmlrpc.php" | grep -c '<methodResponse>')" '^0$'
check "GET xmlrpc.php rejected too"           "$(code "$BASE/xmlrpc.php")" '^403$'

echo "== REST API: anonymous requests refused =="
for route in "/" "/wp/v2/users" "/wp/v2/posts" "/wp/v2/comments" "/batch/v1"; do
	check "anonymous GET rest_route=$route is 401" "$(code "$BASE/?rest_route=$route")" '^401$'
done
check "anonymous response leaks no user data" "$(body "$BASE/?rest_route=/wp/v2/users" | grep -c '"slug"')" '^0$'
check "anonymous POST /wp/v2/comments refused" "$(code -X POST -H 'Content-Type: application/json' --data '{"post":'"$POST_ID"',"content":"x","author_name":"x","author_email":"x@example.org"}' "$BASE/?rest_route=/wp/v2/comments")" '^(401|403)$'

echo "== Comments and trackbacks =="
check "wp-comments-post.php answers 403 (closed)" "$(code -X POST --data "comment_post_ID=$POST_ID&comment=&author=&email=" "$BASE/wp-comments-post.php")" '^403$'
TB="$(body -X POST --data-urlencode "url=http://example.org/wpsl-smoke" --data-urlencode "title=t" --data-urlencode "excerpt=e" --data-urlencode "blog_name=b" "$BASE/wp-trackback.php?p=$POST_ID")"
check "trackback refused"                          "$(grep -o '<error>[0-9]</error>' <<<"$TB")" '<error>1</error>'

echo "== Information disclosure =="
check "?author=N is 404, not a redirect"      "$(curl -s -o /dev/null -m 20 -w '%{http_code}|%{redirect_url}' "$BASE/?author=$AUTHOR_ID")" '^404\|$'
HOME_HTML="$(curl -s -m 20 -D "$TMP/h" "$BASE/")"
check "no generator meta tag"                  "$(grep -ci 'name="generator"' <<<"$HOME_HTML")" '^0$'
check "no REST discovery <link>"               "$(grep -ci 'api.w.org' <<<"$HOME_HTML")" '^0$'
check "no REST discovery Link header"          "$(grep -ci 'api.w.org' "$TMP/h")" '^0$'
check "no X-Pingback header"                   "$(grep -ci '^x-pingback' "$TMP/h")" '^0$'
check "feed has no generator version"          "$(body "$BASE/?feed=rss2" | grep -c 'wordpress.org/?v=')" '^0$'
if [ "${WPSL_REWRITE:-0}" = 1 ]; then
	check "users sitemap is 404"                  "$(code "$BASE/wp-sitemap-users-1.xml")" '^404$'
	check "posts sitemap still available"         "$(code "$BASE/wp-sitemap-posts-post-1.xml")" '^200$'
fi

if [ -n "${WPSL_ADMIN_USER:-}" ] && [ -n "${WPSL_ADMIN_PASS:-}" ]; then
	echo "== Administration still works (cookie + nonce) =="
	login() { # user pass jar
		curl -s -o /dev/null -m 20 -c "$3" -b 'wordpress_test_cookie=WP%20Cookie%20check' --data-urlencode "log=$1" --data-urlencode "pwd=$2" --data-urlencode "testcookie=1" "$BASE/wp-login.php"
		curl -s -m 20 -b "$3" "$BASE/wp-admin/admin-ajax.php?action=rest-nonce"
	}
	ANON="$(login "$WPSL_ADMIN_USER" "$WPSL_ADMIN_PASS" "$TMP/admin.jar")"
	rest() { # jar nonce method route [json]
		local args=(-s -o /dev/null -m 20 -w '%{http_code}' -b "$1" -X "$3"); [ -n "$2" ] && args+=(-H "X-WP-Nonce: $2"); [ -n "${5:-}" ] && args+=(-H 'Content-Type: application/json' --data "$5")
		curl "${args[@]}" "$BASE/?rest_route=$4"
	}
	check "admin obtained a REST nonce"            "${#ANON}" '^[1-9][0-9]*$'
	for route in "/wp/v2/users/me" "/wp/v2/types/post&context=edit" "/wp/v2/settings" "/wp-site-health/v1/directory-sizes" "/"; do
		check "admin GET $route is 200"             "$(rest "$TMP/admin.jar" "$ANON" GET "$route")" '^200$'
	done
	check "admin cookie WITHOUT nonce is anonymous (401)" "$(rest "$TMP/admin.jar" '' GET /wp/v2/users/me)" '^401$'
	check "admin REST comment is refused (403)"     "$(rest "$TMP/admin.jar" "$ANON" POST /wp/v2/comments '{"post":'"$POST_ID"',"content":""}')" '^403$'
	check "admin GET wp-admin/index.php"            "$(code -b "$TMP/admin.jar" "$BASE/wp-admin/index.php")" '^200$'
	check "plugin editor is refused"                "$(code -b "$TMP/admin.jar" "$BASE/wp-admin/plugin-editor.php")" '^(403|500)$'
	check "block editor screen loads"               "$(code -b "$TMP/admin.jar" "$BASE/wp-admin/post-new.php")" '^200$'
	check "dashboard page renders (no fatal error)" "$(body -b "$TMP/admin.jar" "$BASE/wp-admin/options-general.php?page=wp-security-lockdown" | grep -c 'critical error')" '^0$'

	if [ -n "${WPSL_SUB_USER:-}" ] && [ -n "${WPSL_SUB_PASS:-}" ]; then
		echo "== Authorization is preserved for low-privilege users =="
		SN="$(login "$WPSL_SUB_USER" "$WPSL_SUB_PASS" "$TMP/sub.jar")"
		check "subscriber GET /wp/v2/settings is 403"        "$(rest "$TMP/sub.jar" "$SN" GET /wp/v2/settings)" '^403$'
		check "subscriber GET users?context=edit is 403"     "$(rest "$TMP/sub.jar" "$SN" GET '/wp/v2/users&context=edit')" '^403$'
		check "subscriber POST /wp/v2/posts is 403"          "$(rest "$TMP/sub.jar" "$SN" POST /wp/v2/posts '{"title":"x","status":"draft"}')" '^403$'
		check "subscriber cannot open the dashboard page"    "$(code -b "$TMP/sub.jar" "$BASE/wp-admin/options-general.php?page=wp-security-lockdown")" '^(403|302)$'
	fi
fi

echo "== Login errors do not reveal whether a user exists =="
msg() { curl -s -m 20 -b 'wordpress_test_cookie=WP%20Cookie%20check' --data-urlencode "log=$1" --data-urlencode 'pwd=definitely-wrong-pw' --data-urlencode 'testcookie=1' "$BASE/wp-login.php" | grep -o 'id="login_error"[^>]*>.*' | sed 's/<[^>]*>//g' | head -1 | sed 's/^[^:]*Error: *//'; }
UNKNOWN="$(msg "no_such_user_$RANDOM")"
KNOWN="$(msg "${WPSL_SUB_USER:-${WPSL_ADMIN_USER:-admin}}")"
check "same message for unknown user and wrong password" "$([ -n "$UNKNOWN" ] && [ "$UNKNOWN" = "$KNOWN" ] && echo same || echo "different: [$UNKNOWN] vs [$KNOWN]")" '^same$'

if [ "${WPSL_LOCKOUT:-0}" = 1 ]; then
	echo "== Login limiter (this LOCKS the address you run from) =="
	U="${WPSL_SUB_USER:-${WPSL_ADMIN_USER:-admin}}"
	for i in 1 2 3 4 5; do code -b 'wordpress_test_cookie=WP%20Cookie%20check' --data-urlencode "log=$U" --data-urlencode 'pwd=definitely-wrong-pw' --data-urlencode 'testcookie=1' "$BASE/wp-login.php" >/dev/null; done
	check "6th attempt is blocked with HTTP 429"          "$(code -b 'wordpress_test_cookie=WP%20Cookie%20check' --data-urlencode "log=$U" --data-urlencode 'pwd=definitely-wrong-pw' --data-urlencode 'testcookie=1' "$BASE/wp-login.php")" '^429$'
	if [ -n "${WPSL_SUB_PASS:-}${WPSL_ADMIN_PASS:-}" ]; then
		P="${WPSL_SUB_PASS:-$WPSL_ADMIN_PASS}"
		check "a CORRECT password is refused while locked" "$(code -b 'wordpress_test_cookie=WP%20Cookie%20check' --data-urlencode "log=$U" --data-urlencode "pwd=$P" --data-urlencode 'testcookie=1' "$BASE/wp-login.php")" '^429$'
	fi
	echo "NOTE: the lock expires by itself; recovery options are in readme.txt."
fi

echo
echo "passed: $pass  failed: $fail"
exit "$fail"
