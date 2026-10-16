=== WP Security Lockdown ===
Tags: security, hardening, xml-rpc, rest-api, login
Requires at least: 6.0
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

A maximum-security hardening policy for WordPress that tells you which controls are configured, which are enforced, and which are actually proven to work.

== Description ==

WP Security Lockdown reduces a site's attack surface by switching off features most sites do not need, restricting public exposure, and reporting honestly on what it could and could not fix.

Its design rule is: **never mark a control as protected unless a test showed it working.** The dashboard keeps three things apart:

* **Configured**: the policy says the control should be on.
* **Enforced**: the hooks or options are in place right now.
* **Verified**: a test showed the intended effect (a real HTTP request, or a self-test), with the method and the time shown.

A control that is configured but not verified is displayed as "Not verified" and is not counted as protection.

= What it controls =

| Control | What it does | How | Stops when deactivated? |
|---|---|---|---|
| `comments` | No new public comment, trackback or pingback anywhere; existing comments are kept | Filters `comments_open`, `pings_open`, `pre_comment_approved`, `rest_pre_insert_comment`; three discussion defaults | Filters stop; the three defaults persist until rolled back |
| `xmlrpc` | Rejects every request to `xmlrpc.php` with HTTP 403 | Early exit on `plugins_loaded`, before the XML-RPC server loads; filters as defence in depth | Yes |
| `rest_api` | Anonymous REST requests get HTTP 401; optional "dashboard only" mode | `rest_authentication_errors` at priority 110 | Yes |
| `login_limiter` | Temporarily blocks a client address after repeated failed logins; never locks accounts | `authenticate`, `wp_authenticate_user`, `wp_login_failed`; bounded transients | Yes |
| `password_policy` | Minimum password length on profile, add-user, reset and REST user screens | Core hooks | Yes |
| `login_errors` | Same message for unknown user and wrong password | `wp_login_errors`, `rest_authentication_errors` | Yes |
| `author_enumeration` | `?author=N` answers 404; no users sitemap; no anonymous `/wp/v2/users` | `template_redirect`, `wp_sitemaps_add_provider`, `rest_endpoints` | Yes |
| `version_exposure` | No generator tag, no WordPress version in script/style URLs | Core hooks | Yes |
| `discovery` | No REST / oEmbed / shortlink advertisements | Removes core hooks | Yes |
| `error_display` | PHP errors are not printed into pages (not on local/development environments) | `ini_set( 'display_errors', 0 )` at load | Yes |
| `file_editor` | Theme and plugin code editors disabled | `DISALLOW_FILE_EDIT` when undefined, plus a `map_meta_cap` filter | Yes |
| `updates` | **Monitor only.** Reports whether security updates can actually install and what is pending | Read-only | n/a |

Hiding the WordPress version or discovery links is hygiene, not protection. Patching and access control are what protect a site, and the plugin says so on the dashboard.

= What it will never do =

* Edit `wp-config.php`, change file ownership or permissions, or write server configuration.
* Disable core, plugin or theme updates (`DISALLOW_FILE_MODS` is never set; `automatic_updater_disabled` and friends are never touched). A test scans the source for this.
* Delete comments, users, posts, uploads, plugins or themes.
* Delete its audit log or its record of changed settings on deactivation or uninstall.
* Send security headers from PHP. It audits them and gives you server configuration to review, because PHP-set headers miss static files and a wrong Content-Security-Policy breaks sites.
* Claim multifactor authentication is enforced. It only reports whether an MFA plugin is present.

== Installation ==

1. Copy the `wp-security-lockdown` folder to `wp-content/plugins/` and activate it on the site (network activation is refused).
2. Open **Settings > Security Lockdown**. Right after activation every control shows "Not verified" except those the plugin can prove inside PHP.
3. Press **Run verification and diagnostics**. This sends a bounded number of real requests to your own site (at most 40, within 25 seconds) and records, per control, whether the effect was observed.
4. Read the **Checks** tab: it lists weaknesses a plugin cannot fix (web server, filesystem, database account, accounts) and says who has to act.
5. Review **Compatibility warnings** before relying on the REST, XML-RPC or comments controls with Jetpack, WooCommerce, Contact Form 7 or remote publishing tools.

A WP-Cron job also runs the HTTP verification about 30 seconds after activation. It cannot run during the activation request itself: WordPress runs the activation callback before it adds the plugin to the list of active plugins, so a request sent at that moment would reach a site where the plugin is not active yet.

== Lifecycle ==

= Activation =

1. Validates PHP (7.4+) and WordPress (6.0+); otherwise activation is refused with a message.
2. Creates the default policy if none exists. An existing policy is never overwritten.
3. Registers the hooks and applies the policy to the three discussion options **idempotently**, recording each option's original value once, the first time the plugin changes it.
4. Verifies the effective state inside PHP, records the result, and schedules the HTTP verification.
5. Records success, failure and compatibility warnings in the audit log. An internal error never fatals activation; it is logged and shown.

Repeated activation does not duplicate the ledger, does not overwrite the recorded originals and does not change any option other than the three documented ones.

= Deactivation =

* **Stops immediately:** every runtime protection (comment and ping filters, XML-RPC rejection, REST policy, login limiter and lockouts, disclosure filters, file-editor block).
* **Persists:** the three discussion defaults (`default_comment_status`, `default_ping_status`, `default_pingback_flag`), the policy settings, the change record and the audit log.
* **Optional:** the setting "Restore original settings when the plugin is deactivated" rolls back on deactivation using the conflict-aware logic below.
* Temporary lockouts, the verification cron event and cached diagnostics are removed.

= Rollback =

**Settings > Security Lockdown > Rollback and recovery** lists the options the plugin changed with their original, applied and current values. Rollback restores only plugin-owned changes and never overwrites a value that was changed after the plugin set it: that is reported as a **conflict** and left alone, unless you tick the explicit "also overwrite" box. Controls whose settings were all handed back are switched off in the policy so that they do not re-apply them.

= Uninstall =

Deleting the plugin removes the policy settings, lockout counters, cached diagnostics and scheduled events. It **keeps** the audit log (`wp_security_lockdown_audit_log`) and the change record (`wp_security_lockdown_state`), and never touches site content. Remove them by hand if you want them gone: `wp option delete wp_security_lockdown_audit_log wp_security_lockdown_state`.

== Recovery ==

These work without the dashboard:

* **Locked out by the login limiter:** wait for the block to expire (default 15 minutes), use another network, or add `define( 'WP_SECURITY_LOCKDOWN_DISABLE_LOGIN_LIMITER', true );` to `wp-config.php`.
* **Switch the whole plugin off without touching files:** add `define( 'WP_SECURITY_LOCKDOWN_DISABLE', true );` to `wp-config.php`. Nothing from the plugin runs and nothing stored is changed.
* **Fatal error or white screen:** rename the plugin folder, for example `mv wp-content/plugins/wp-security-lockdown wp-content/plugins/wp-security-lockdown.off`. WordPress deactivates a missing plugin automatically. WordPress Recovery Mode also applies.
* **WP-CLI:** `wp plugin deactivate wp-security-lockdown`.
* **Undo the persistent options by hand:** Settings > Discussion.

== Compatibility and potentially breaking behaviour ==

* **XML-RPC blocked (default).** Breaks Jetpack's WordPress.com connection, older WordPress mobile apps, desktop blog editors and MetaWeblog/Blogger clients, and some IFTTT/Zapier actions. Switch XML-RPC to "Allow" if you depend on it; pingback methods are removed in both modes. Use the REST API with Application Passwords (HTTPS required) instead.
* **REST API restricted (default).** Anonymous requests get 401. Block themes, the dashboard, the block editor and Site Health keep working because they authenticate with a logged-in cookie and nonce. Breaks anything that calls the API anonymously: headless front ends, mobile apps, WooCommerce block checkout (allowlist `wc/store/v1`), Contact Form 7 (allowlist `contact-form-7/v1`), some Jetpack features. Core admin namespaces cannot be allowlisted on purpose.
* **REST "dashboard only" mode (opt-in, potentially breaking).** Only the wp-admin UI (cookie and nonce) may use the API, and only on core admin namespaces plus ones you list. Application-password and token clients, third-party namespaces and anonymous visitors are all refused. A literal "REST off for everyone" is not offered because the block editor, site editor, Site Health and profile screens cannot work without it.
* **Comments disabled (default).** WooCommerce product reviews are comments and are closed too. Editor **Notes** (comment type `note`, WordPress 6.9+) are not public comments and keep working. Programmatic `wp_insert_comment()` calls (importers, system log comments) are not blocked.
* **Login limiter.** Blocks client addresses, never accounts. Behind a reverse proxy you **must** declare the proxy ranges and the client-IP header; otherwise the limiter detects that all visitors would share one address and fails open (it stops counting, and the dashboard says "Partially enforced"). It does not rate-limit REST application-password failures or password-reset requests; use fail2ban or a WAF for network-level blocking.
* **Author enumeration.** With plain permalinks `?author=N` is the canonical author URL and cannot be blocked; the dashboard reports the control as partial.
* **Removing discovery links** stops clients that auto-discover the REST API from finding it.

== Server-level actions that remain necessary ==

A PHP plugin cannot do these; the Checks tab detects and explains them:

* HTTPS and an HTTP to HTTPS redirect; HSTS only after HTTPS works everywhere.
* Security headers (`X-Content-Type-Options`, `X-Frame-Options` / `frame-ancestors`, `Referrer-Policy`, `Permissions-Policy`) and a Content-Security-Policy built with `Content-Security-Policy-Report-Only` first. Suggested Apache and nginx directives are generated, without CSP.
* Denying `readme.html`, `license.txt`, `.git`, config backups, `.env` and directory listings at the web server.
* No PHP execution inside `wp-content/uploads`.
* File ownership and permissions (`wp-config.php` not world-readable; no world-writable directories). The plugin only reports.
* `display_errors = Off` and `expose_php = Off` in `php.ini`, and a supported PHP version.
* A dedicated, least-privilege database user instead of `root`.
* A multifactor-authentication plugin, required for privileged users.
* Network-level blocking of repeat attackers.

== Security design notes ==

* **Authorization:** every state-changing admin action is an HTTP POST, checked for the `manage_options` capability first and then for an action-specific nonce. A nonce is never treated as authorization. Settings go through the Settings API (`options.php`) and one strict sanitizer; unknown keys are discarded, numbers are clamped, IP lists are validated, and core admin REST namespaces cannot be made public.
* **Output:** all dashboard output is escaped for its context; messages shown after a redirect come from a fixed table, never from request parameters; stored data (log, ledger, cached checks) is treated as untrusted and coerced on read.
* **Logging:** a bounded ring buffer (200 entries, one database write per request), never autoloaded, never emptied by deactivation or uninstall. It never records passwords, user names, cookies or tokens (people sometimes type a password into the user name field); client addresses are stored anonymized; lockout events are throttled so an attack cannot flood it.
* **Login limiter storage:** counters live in 64 transient shards of at most 100 entries each (a hard upper bound however many addresses attack), keyed by a keyed hash of the client address (IPv6 by /64), never the address itself. Every counter and lock expires. Counting is best effort (not atomic): under heavy concurrency it can miss a few failures; it never over-counts.
* **Client address:** `REMOTE_ADDR` only, unless you configure trusted proxies AND a header; `X-Forwarded-For` is read right to left, skipping your own proxies. Shared proxy addresses (private ranges and 100.64.0.0/10) are detected and never punished.
* **Probes:** the loopback requests only target this site's own host, are bounded in number and time, never follow redirects, are skipped entirely if a preflight request fails, and never carry content that could create a comment. The administrator's session cookie is forwarded to this site only, for the authenticated REST probe, and is never stored or logged.
* **Performance:** hook registration performs no database query and no I/O; diagnostics, probes and the uploads scan run only on demand and their results are stored with a timestamp.

== Known limitations ==

* HTTP verification needs the site to be able to reach itself over HTTP. Where it cannot (some hosts, Docker/NAT), the affected controls stay "Not verified"; they are never marked verified.
* The authenticated half of the REST verification needs an interactive administrator session; the cron-run verification skips it and the detail says so.
* Login-limiter verification is a self-test of the logic and storage with a synthetic key. No real login attempts are made, because they would count against (and could lock) your own address. Cross-request persistence is covered by the test suite and the black-box checks, not by the dashboard.
* The uploads protection check is heuristic (it can see Apache `.htaccess` rules in the uploads folder, not nginx or main-server configuration).
* Multisite has not been tested; network-wide activation is refused. Translations are not shipped (the text domain is `wp-security-lockdown`).
* `display_errors` can only be changed for code that runs after this plugin loads.
* Tested against WordPress 7.1.3 on PHP 8.1. The code avoids syntax newer than PHP 7.4 (checked by a token scan), but PHP 7.4 and WordPress 6.x were not run.

== Running the tests ==

The tests are `WP_UnitTestCase` tests for the WordPress test library. They wipe their database, so use a **throwaway database**.

1. Get the WordPress test library for your WordPress version (the `tests/phpunit/includes` and `tests/phpunit/data` folders of `wordpress-develop`), the Yoast PHPUnit Polyfills, and PHPUnit 9.6.
2. Create `wp-tests-config.php` for an empty throwaway database.
3. Run:

`WP_TESTS_DIR=/path/to/tests/phpunit WP_TESTS_CONFIG_FILE_PATH=/path/to/wp-tests-config.php WP_TESTS_PHPUNIT_POLYFILLS_PATH=/path/to/phpunit-polyfills php phpunit.phar -c phpunit.xml.dist`

`tests/http-smoke.sh` is a black-box script for a **disposable** copy of a site with the plugin active: it checks the observable HTTP behaviour (XML-RPC, REST, comments, author enumeration, login lockout) with plain curl. `composer.json` and `phpcs.xml.dist` are provided for the WordPress Coding Standards.

== Changelog ==

= 1.0.0 =
* Initial release.
