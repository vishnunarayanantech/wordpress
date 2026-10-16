<?php
/**
 * Diagnostics for weaknesses a plugin cannot fix by itself.
 *
 * @package WP_Security_Lockdown
 */

namespace WP_Security_Lockdown;

defined( 'ABSPATH' ) || exit;

/**
 * Produces "checks": findings that need a human or a server-level change.
 *
 * Cheap checks (configuration only) run live. Deep checks (HTTP requests to this site, the
 * uploads scan, wordpress.org's PHP support data) run only when an administrator asks or from the
 * one-off cron job after activation, and are stored with a timestamp. A normal page view never
 * makes a request or scans the disk.
 *
 * Row: id, group, title, status (pass|warn|fail|info), summary, remediation, requires (''|manual|server), deep.
 *
 * Nothing here changes the site. Every remediation is text for a human.
 */
class Health_Check {

	/** Known multifactor-authentication plugins (detection by plugin file; this proves presence only). */
	const MFA_PLUGINS = array(
		'two-factor/two-factor.php'                      => 'Two Factor',
		'wp-2fa/wp-2fa.php'                              => 'WP 2FA',
		'wordfence/wordfence.php'                        => 'Wordfence (Login Security)',
		'wordfence-login-security/wordfence-login-security.php' => 'Wordfence Login Security',
		'miniorange-2-factor-authentication/miniorange_2_factor_settings.php' => 'miniOrange 2FA',
		'google-authenticator/google-authenticator.php'  => 'Google Authenticator',
		'duo-wordpress/duo_wordpress.php'                => 'Duo Two-Factor Authentication',
		'two-factor-authentication/two-factor-login.php' => 'Two Factor Authentication',
		'solid-security/solid-security.php'              => 'Solid Security',
		'ithemes-security-pro/ithemes-security-pro.php'  => 'iThemes Security Pro',
	);

	/**
	 * Service container.
	 *
	 * @var Plugin
	 */
	private $plugin;

	/**
	 * Service container.
	 *
	 * @param Plugin $plugin Service container.
	 */
	public function __construct( Plugin $plugin ) {
		$this->plugin = $plugin;
	}

	/**
	 * Drops cached diagnostics (called on deactivation).
	 *
	 * @return void
	 */
	public static function clear_caches() {
		delete_transient( Modules\Update_Policy::FS_TRANSIENT );
	}

	/**
	 * Cheap checks plus the stored result of the last deep run.
	 *
	 * @return array {
	 *     @type array[] $rows      All rows (live + stored).
	 *     @type int     $deep_time When the deep rows were produced (0 = never).
	 * }
	 */
	public function all() {
		$rows = array();
		foreach ( $this->live_checks() as $row ) {
			$rows[ $row['id'] ] = $row;
		}

		$stored = $this->plugin->state()->get( 'checks' );
		$time   = isset( $stored['time'] ) ? (int) $stored['time'] : 0;
		if ( ! empty( $stored['rows'] ) && is_array( $stored['rows'] ) ) {
			foreach ( $stored['rows'] as $row ) {
				$row = $this->valid_row( $row );
				if ( null !== $row ) {
					$rows[ $row['id'] ] = $row;
					// A deep result replaces its live placeholder, keeping its position.
				}
			}
		}
		return array(
			'rows'      => array_values( $rows ),
			'deep_time' => $time,
		);
	}

	/**
	 * Accepts a stored row only if it has the documented shape; everything is coerced to safe scalars.
	 *
	 * @param mixed $row Stored value.
	 * @return array|null
	 */
	private function valid_row( $row ) {
		if ( ! is_array( $row ) ) {
			return null;
		}
		$out = array();
		foreach ( array( 'id', 'group', 'title', 'summary', 'remediation' ) as $key ) {
			if ( ! isset( $row[ $key ] ) || ! is_scalar( $row[ $key ] ) ) {
				return null;
			}
			$out[ $key ] = (string) $row[ $key ];
		}
		$out['status']   = isset( $row['status'] ) && in_array( $row['status'], array( 'pass', 'warn', 'fail', 'info' ), true ) ? $row['status'] : 'info';
		$out['requires'] = isset( $row['requires'] ) && in_array( $row['requires'], array( '', 'manual', 'server' ), true ) ? $row['requires'] : '';
		$out['deep']     = true;
		$out['snippet']  = isset( $row['snippet'] ) && is_array( $row['snippet'] ) ? array_filter( $row['snippet'], 'is_string' ) : array();
		return $out;
	}

	/**
	 * Runs the deep checks and stores them.
	 *
	 * @param bool            $deep  Must be true; kept so cron can call run( true ) uniformly.
	 * @param Http_Probe|null $probe Probe to use (a new budgeted one otherwise).
	 * @return array[] The deep rows.
	 */
	public function run( $deep = true, ?Http_Probe $probe = null ) {
		if ( ! $deep ) {
			return $this->live_checks();
		}
		$probe = $probe ? $probe : new Http_Probe();
		$rows  = array();

		foreach ( $this->plugin->policy()->modules() as $module ) {
			if ( $module instanceof Modules\File_Security ) {
				foreach ( $module->diagnostics( true ) as $row ) {
					// The cheap file rows are already live; keep only the deep one(s) here.
					if ( 'uploads_exec' === $row['id'] ) {
						$rows[] = $row;
					}
				}
			}
		}

		$rows[] = $this->check_php_version( true );
		$rows   = array_merge( $rows, $this->check_exposure( $probe ) );
		$rows   = array_merge( $rows, $this->check_headers( $probe ) );

		foreach ( $rows as $i => $row ) {
			$rows[ $i ]['deep'] = true;
		}
		$this->plugin->state()->set(
			'checks',
			array(
				'time' => time(),
				'rows' => $rows,
			)
		);
		$this->plugin->logger()->info(
			'diagnostics_run',
			'Deep diagnostics were run.',
			array(
				'rows'     => count( $rows ),
				'requests' => $probe->requests_made(),
			)
		);
		return $rows;
	}

	/**
	 * Counts for the overview: failures, warnings, and findings that need a human / the server.
	 *
	 * @param array[] $rows Rows.
	 * @return array
	 */
	public static function summarize( array $rows ) {
		$out = array(
			'fail'   => 0,
			'warn'   => 0,
			'manual' => 0,
			'server' => 0,
		);
		foreach ( $rows as $row ) {
			if ( isset( $out[ $row['status'] ] ) ) {
				++$out[ $row['status'] ];
			}
			if ( in_array( $row['status'], array( 'fail', 'warn' ), true ) && isset( $out[ $row['requires'] ] ) ) {
				++$out[ $row['requires'] ];
			}
		}
		return $out;
	}

	/**
	 * Group slug => label.
	 *
	 * @return array
	 */
	public static function groups() {
		return array(
			'environment' => __( 'Environment', 'wp-security-lockdown' ),
			'auth'        => __( 'Accounts and authentication', 'wp-security-lockdown' ),
			'files'       => __( 'Files and permissions', 'wp-security-lockdown' ),
			'exposure'    => __( 'Public exposure of sensitive files', 'wp-security-lockdown' ),
			'headers'     => __( 'Security headers (set at the web server)', 'wp-security-lockdown' ),
		);
	}

	/* ===================================================================== live checks */

	/**
	 * Runs the checks that need no network and no heavy I/O, so they are safe on every dashboard view.
	 *
	 * @return array[]
	 */
	public function live_checks() {
		$rows = array(
			$this->check_https(),
			$this->check_database_user(),
			$this->check_debug(),
			$this->check_php_version( false ),
			$this->check_admin_username(),
			$this->check_registration(),
			$this->check_mfa(),
		);

		foreach ( $this->plugin->policy()->modules() as $module ) {
			if ( $module instanceof Modules\File_Security ) {
				$rows = array_merge( $rows, $module->diagnostics( false ) );
			}
		}
		foreach ( $rows as $i => $row ) {
			$rows[ $i ]['deep'] = false;
		}
		return $rows;
	}

	/**
	 * Checks that the site address uses HTTPS.
	 *
	 * @return array
	 */
	private function check_https() {
		$title   = __( 'HTTPS', 'wp-security-lockdown' );
		$home    = home_url();
		$secure  = 0 === strpos( $home, 'https://' );
		$dev_env = in_array( wp_get_environment_type(), array( 'local', 'development' ), true );

		if ( $secure ) {
			if ( ! is_ssl() ) {
				return self::row( 'https', 'environment', $title, 'info', __( 'The site address uses https://, but this request arrived over plain HTTP. Redirect HTTP to HTTPS at the web server.', 'wp-security-lockdown' ), __( 'Add a permanent HTTP to HTTPS redirect in the web server or CDN.', 'wp-security-lockdown' ), 'server' );
			}
			return self::row( 'https', 'environment', $title, 'pass', __( 'The site address uses HTTPS.', 'wp-security-lockdown' ), '', '' );
		}
		return self::row(
			'https',
			'environment',
			$title,
			$dev_env ? 'info' : 'warn',
			__( 'The site address uses plain http://. Logins, session cookies and REST nonces travel unencrypted, and WordPress will not offer Application Passwords.', 'wp-security-lockdown' ),
			__( 'Install a TLS certificate, redirect HTTP to HTTPS, then update the WordPress Address and Site Address. Consider defining FORCE_SSL_ADMIN in wp-config.php.', 'wp-security-lockdown' ),
			'server'
		);
	}

	/**
	 * Checks that WordPress does not connect as the MySQL root user.
	 *
	 * @return array
	 */
	private function check_database_user() {
		$title = __( 'Database account privileges', 'wp-security-lockdown' );
		if ( defined( 'DB_USER' ) && 0 === strcasecmp( (string) DB_USER, 'root' ) ) {
			return self::row(
				'db_user',
				'environment',
				$title,
				'fail',
				__( 'WordPress connects to the database as the MySQL "root" superuser. A SQL injection or a compromised plugin then reaches every database on the server and can often read or write files.', 'wp-security-lockdown' ),
				__( 'Create a dedicated MySQL user with privileges only on this site\'s database (SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, DROP, INDEX) and put it in wp-config.php. Do this deliberately, with a database backup: the plugin never edits wp-config.php.', 'wp-security-lockdown' ),
				'manual'
			);
		}
		return self::row( 'db_user', 'environment', $title, 'pass', __( 'WordPress does not connect as the MySQL root user.', 'wp-security-lockdown' ), '', '' );
	}

	/**
	 * Checks the debug and error-display settings.
	 *
	 * @return array
	 */
	private function check_debug() {
		$title  = __( 'Debug settings', 'wp-security-lockdown' );
		$prod   = ! in_array( wp_get_environment_type(), array( 'local', 'development' ), true );
		$notes  = array();
		$status = 'pass';

		$debug   = defined( 'WP_DEBUG' ) && WP_DEBUG;
		$display = $debug && ( ! defined( 'WP_DEBUG_DISPLAY' ) || WP_DEBUG_DISPLAY );
		$log     = defined( 'WP_DEBUG_LOG' ) && WP_DEBUG_LOG;

		if ( $debug && $prod ) {
			$status  = 'warn';
			$notes[] = __( 'WP_DEBUG is on in a production environment.', 'wp-security-lockdown' );
		}
		if ( $display && $prod ) {
			$status  = 'fail';
			$notes[] = __( 'WP_DEBUG_DISPLAY is on, so PHP errors (with file paths) are printed in pages.', 'wp-security-lockdown' );
		}
		if ( $log ) {
			$status  = 'fail' === $status ? 'fail' : 'warn';
			$notes[] = __( 'WP_DEBUG_LOG is on. By default the log is wp-content/debug.log, which web servers serve to anyone who guesses the URL unless it is denied (the deep exposure check below tests this).', 'wp-security-lockdown' );
		}
		if ( Modules\Information_Disclosure::display_errors_on() && $prod ) {
			$status  = 'fail';
			$notes[] = __( 'PHP display_errors is on for this request.', 'wp-security-lockdown' );
		}

		if ( ! $notes ) {
			return self::row( 'debug', 'environment', $title, 'pass', __( 'Debug output is off and errors are not displayed.', 'wp-security-lockdown' ), '', '' );
		}
		return self::row(
			'debug',
			'environment',
			$title,
			$status,
			implode( ' ', $notes ),
			__( 'In wp-config.php set WP_DEBUG to false on production (or keep WP_DEBUG_DISPLAY false and write WP_DEBUG_LOG to a path outside the web root), and set display_errors = Off in php.ini.', 'wp-security-lockdown' ),
			'manual'
		);
	}

	/**
	 * Uses WordPress.org's own PHP support data (the same source Site Health uses).
	 *
	 * @param bool $allow_http Whether a network request to wordpress.org is acceptable.
	 * @return array
	 */
	private function check_php_version( $allow_http ) {
		$title  = __( 'PHP version', 'wp-security-lockdown' );
		$cached = get_site_transient( 'php_check_' . md5( PHP_VERSION ) );
		if ( false === $cached && ! $allow_http ) {
			return self::row(
				'php_version',
				'environment',
				$title,
				'info',
				sprintf(
					/* translators: %s: PHP version. */
					__( 'This site runs PHP %s. Whether that branch still receives security fixes has not been checked yet: run diagnostics.', 'wp-security-lockdown' ),
					PHP_VERSION
				),
				'',
				''
			);
		}

		if ( ! function_exists( 'wp_check_php_version' ) ) {
			require_once ABSPATH . 'wp-admin/includes/misc.php';
		}
		$info = wp_check_php_version();
		if ( ! is_array( $info ) ) {
			return self::row( 'php_version', 'environment', $title, 'info', __( 'Could not determine PHP support status (wordpress.org could not be reached).', 'wp-security-lockdown' ), '', '' );
		}

		$recommended = isset( $info['recommended_version'] ) ? sanitize_text_field( (string) $info['recommended_version'] ) : '';
		if ( isset( $info['is_secure'] ) && ! $info['is_secure'] ) {
			return self::row(
				'php_version',
				'environment',
				$title,
				'fail',
				sprintf(
					/* translators: %s: PHP version. */
					__( 'PHP %s no longer receives security fixes. Known vulnerabilities in it will never be patched.', 'wp-security-lockdown' ),
					PHP_VERSION
				),
				sprintf(
					/* translators: %s: recommended PHP version. */
					__( 'Upgrade PHP (WordPress recommends %s or newer) through your host or server configuration, after testing your plugins and theme.', 'wp-security-lockdown' ),
					'' !== $recommended ? $recommended : __( 'the current stable release', 'wp-security-lockdown' )
				),
				'server'
			);
		}
		if ( isset( $info['is_supported'] ) && ! $info['is_supported'] ) {
			return self::row( 'php_version', 'environment', $title, 'warn', sprintf( /* translators: %s: PHP version. */ __( 'PHP %s only receives security fixes now (no longer actively supported). Plan an upgrade.', 'wp-security-lockdown' ), PHP_VERSION ), '', 'server' );
		}
		return self::row( 'php_version', 'environment', $title, 'pass', sprintf( /* translators: %s: PHP version. */ __( 'PHP %s is supported.', 'wp-security-lockdown' ), PHP_VERSION ), '', '' );
	}

	/**
	 * Checks for a predictable administrator account name.
	 *
	 * @return array
	 */
	private function check_admin_username() {
		$title = __( 'Predictable administrator account name', 'wp-security-lockdown' );
		if ( username_exists( 'admin' ) ) {
			return self::row(
				'admin_username',
				'auth',
				$title,
				'warn',
				__( 'A user named "admin" exists. It is the first name every password-guessing bot tries.', 'wp-security-lockdown' ),
				__( 'Create a new administrator with a non-obvious login, log in as it, then delete "admin" (reassigning its content) or demote it. Also check that its author slug is not "admin".', 'wp-security-lockdown' ),
				'manual'
			);
		}
		return self::row( 'admin_username', 'auth', $title, 'pass', __( 'No user is named "admin".', 'wp-security-lockdown' ), '', '' );
	}

	/**
	 * Checks that open registration does not grant a privileged role.
	 *
	 * @return array
	 */
	private function check_registration() {
		$title = __( 'Open registration', 'wp-security-lockdown' );
		if ( ! get_option( 'users_can_register' ) ) {
			return self::row( 'registration', 'auth', $title, 'pass', __( 'Public registration is closed.', 'wp-security-lockdown' ), '', '' );
		}
		$role = (string) get_option( 'default_role' );
		if ( 'subscriber' !== $role ) {
			return self::row(
				'registration',
				'auth',
				$title,
				'fail',
				sprintf(
					/* translators: %s: role slug. */
					__( 'Anyone can register and is given the "%s" role. That is a privilege-escalation hole.', 'wp-security-lockdown' ),
					sanitize_key( $role )
				),
				__( 'Settings > General: set "New User Default Role" to Subscriber, or close registration.', 'wp-security-lockdown' ),
				'manual'
			);
		}
		return self::row( 'registration', 'auth', $title, 'info', __( 'Public registration is open with the Subscriber role (the safe default). Make sure you want strangers to have accounts.', 'wp-security-lockdown' ), '', '' );
	}

	/**
	 * Reports whether a multifactor plugin exists. It cannot tell whether MFA is ENFORCED for privileged users,
	 * so the best possible status is "info", never "pass".
	 *
	 * @return array
	 */
	private function check_mfa() {
		$title  = __( 'Multifactor authentication', 'wp-security-lockdown' );
		$active = (array) get_option( 'active_plugins', array() );
		$found  = array();
		foreach ( self::MFA_PLUGINS as $file => $name ) {
			if ( in_array( $file, $active, true ) ) {
				$found[] = $name;
			}
		}
		if ( $found ) {
			return self::row(
				'mfa',
				'auth',
				$title,
				'info',
				sprintf(
					/* translators: %s: plugin names. */
					__( 'Detected: %s. This plugin cannot verify that multifactor authentication is actually required for administrators and editors; confirm that in that plugin\'s own settings.', 'wp-security-lockdown' ),
					implode( ', ', $found )
				),
				__( 'Require MFA for every account that can publish or manage the site, and keep recovery codes safe.', 'wp-security-lockdown' ),
				'manual'
			);
		}
		return self::row(
			'mfa',
			'auth',
			$title,
			'warn',
			__( 'WordPress has no built-in multifactor authentication and none of the well-known MFA plugins is active. MFA is NOT available or enforced on this site.', 'wp-security-lockdown' ),
			__( 'Install a maintained MFA plugin (for example the "Two Factor" plugin from the WordPress team) and require it for administrators. This plugin does not implement authentication itself.', 'wp-security-lockdown' ),
			'manual'
		);
	}

	/* ===================================================================== deep checks */

	/**
	 * Requests a short list of paths that must never be public. Response bodies are inspected in memory
	 * and discarded; nothing from them is stored or shown.
	 *
	 * @param Http_Probe $probe Probe.
	 * @return array[]
	 */
	private function check_exposure( Http_Probe $probe ) {
		$preflight = $probe->preflight();
		if ( ! $preflight['ok'] ) {
			$reason = sprintf( /* translators: %s: error code. */ __( 'Skipped: HTTP probe unavailable (%s).', 'wp-security-lockdown' ), $preflight['error'] );
			return array(
				self::row( 'exposed_files', 'exposure', __( 'Sensitive files reachable over HTTP', 'wp-security-lockdown' ), 'info', $reason, '', '' ),
			);
		}

		$sensitive = array(
			'.git/HEAD (WordPress root)' => array( site_url( '/.git/HEAD' ), 'git' ),
			'.git/HEAD (wp-content)'     => array( content_url( '/.git/HEAD' ), 'git' ),
			'wp-config.php.bak'          => array( site_url( '/wp-config.php.bak' ), 'config' ),
			'wp-config.php.old'          => array( site_url( '/wp-config.php.old' ), 'config' ),
			'wp-config.php.save'         => array( site_url( '/wp-config.php.save' ), 'config' ),
			'wp-config.php.orig'         => array( site_url( '/wp-config.php.orig' ), 'config' ),
			'wp-config.php~'             => array( site_url( '/wp-config.php~' ), 'config' ),
			'wp-config.txt'              => array( site_url( '/wp-config.txt' ), 'config' ),
			'.env'                       => array( site_url( '/.env' ), 'env' ),
			'wp-content/debug.log'       => array( content_url( '/debug.log' ), 'log' ),
		);

		$hits     = array();
		$answered = 0;
		foreach ( $sensitive as $label => $target ) {
			$response = $probe->request( 'GET', $target[0] );
			if ( ! $response['ok'] ) {
				continue;
			}
			++$answered;
			if ( 200 === $response['code'] && $this->looks_sensitive( $target[1], $response ) ) {
				$hits[] = $label;
			}
		}

		$rows = array();
		if ( $hits ) {
			$rows[] = self::row(
				'exposed_files',
				'exposure',
				__( 'Sensitive files reachable over HTTP', 'wp-security-lockdown' ),
				'fail',
				sprintf(
					/* translators: %s: list of paths. */
					__( 'These paths answered with readable content: %s. Anyone can download them.', 'wp-security-lockdown' ),
					implode( ', ', $hits )
				),
				__( 'Deny them at the web server immediately (Apache: <FilesMatch> / "Require all denied"; nginx: "location ~ /\\.(git|env) { deny all; }" and a rule for backup suffixes), then remove the files. If a config backup or .env was exposed, rotate every secret in it.', 'wp-security-lockdown' ),
				'server'
			);
		} elseif ( $answered > 0 ) {
			$rows[] = self::row(
				'exposed_files',
				'exposure',
				__( 'Sensitive files reachable over HTTP', 'wp-security-lockdown' ),
				'pass',
				sprintf(
					/* translators: %d: number of paths. */
					__( 'None of %d commonly leaked paths (version-control metadata, config backups, .env, debug.log) returned readable content. This is a short list, not a vulnerability scan.', 'wp-security-lockdown' ),
					$answered
				),
				'',
				''
			);
		} else {
			$rows[] = self::row( 'exposed_files', 'exposure', __( 'Sensitive files reachable over HTTP', 'wp-security-lockdown' ), 'info', __( 'The requests could not be completed.', 'wp-security-lockdown' ), '', '' );
		}//end if

		$version_files = array();
		foreach ( array(
			'readme.html' => site_url( '/readme.html' ),
			'license.txt' => site_url( '/license.txt' ),
		) as $label => $url ) {
			$response = $probe->request( 'GET', $url );
			if ( $response['ok'] && 200 === $response['code'] ) {
				$version_files[] = $label;
			}
		}
		$rows[] = $version_files
			? self::row(
				'version_files',
				'exposure',
				__( 'Version-revealing static files', 'wp-security-lockdown' ),
				'warn',
				sprintf(
					/* translators: %s: file names. */
					__( '%s are publicly reachable and state the WordPress version. They are static files, so PHP cannot hide them, and deleting them is undone by every core update.', 'wp-security-lockdown' ),
					implode( ' and ', $version_files )
				),
				__( 'Deny them at the web server (Apache: <FilesMatch "^(readme\\.html|license\\.txt)$"> Require all denied </FilesMatch>; nginx: location ~* ^/(readme\\.html|license\\.txt)$ { deny all; }).', 'wp-security-lockdown' ),
				'server'
			)
			: self::row( 'version_files', 'exposure', __( 'Version-revealing static files', 'wp-security-lockdown' ), 'pass', __( 'readme.html and license.txt are not publicly readable.', 'wp-security-lockdown' ), '', '' );

		$listing = array();
		foreach ( array(
			'wp-content/uploads/' => content_url( '/uploads/' ),
			'wp-includes/'        => includes_url( '/' ),
		) as $label => $url ) {
			$response = $probe->request( 'GET', $url );
			if ( $response['ok'] && 200 === $response['code'] && false !== stripos( $response['body'], 'Index of' ) ) {
				$listing[] = $label;
			}
		}
		$rows[] = $listing
			? self::row(
				'directory_listing',
				'exposure',
				__( 'Directory listing', 'wp-security-lockdown' ),
				'warn',
				sprintf(
					/* translators: %s: directories. */
					__( 'The web server lists the contents of: %s.', 'wp-security-lockdown' ),
					implode( ', ', $listing )
				),
				__( 'Disable directory indexes (Apache: "Options -Indexes"; nginx: "autoindex off;").', 'wp-security-lockdown' ),
				'server'
			)
			: self::row( 'directory_listing', 'exposure', __( 'Directory listing', 'wp-security-lockdown' ), 'pass', __( 'Directory listing is not enabled for uploads or wp-includes.', 'wp-security-lockdown' ), '', '' );

		return $rows;
	}

	/**
	 * Decides whether a 200 response is really the sensitive thing and not a soft-404 page.
	 *
	 * @param string $kind     git | config | env | log.
	 * @param array  $response Probe response.
	 * @return bool
	 */
	private function looks_sensitive( $kind, array $response ) {
		$type = isset( $response['headers']['content-type'] ) ? strtolower( $response['headers']['content-type'] ) : '';
		$body = $response['body'];
		switch ( $kind ) {
			case 'git':
				return 1 === preg_match( '/^ref:\s/m', $body );
			case 'config':
				// A leaked backup is served as plain text / octet-stream; an HTML page that merely mentions DB_NAME is a soft 404.
				return false === strpos( $type, 'html' ) && ( false !== strpos( $body, 'DB_NAME' ) || false !== strpos( $body, 'DB_PASSWORD' ) || false !== strpos( $body, 'table_prefix' ) );
			case 'env':
				return false === strpos( $type, 'html' ) && 1 === preg_match( '/^[A-Z][A-Z0-9_]{2,}\s*=/m', $body );
			case 'log':
				return false === strpos( $type, 'html' ) && '' !== trim( $body );
		}
		return false;
	}

	/**
	 * Audits the front page's response headers.
	 *
	 * @param Http_Probe $probe Probe.
	 * @return array[]
	 */
	private function check_headers( Http_Probe $probe ) {
		$preflight = $probe->preflight();
		$front     = $preflight['ok'] ? $probe->request( 'GET', home_url( '/' ) ) : null;
		if ( ! $front || ! $front['ok'] ) {
			return array(
				self::row( 'headers', 'headers', __( 'Security headers', 'wp-security-lockdown' ), 'info', __( 'Skipped: the front page could not be fetched.', 'wp-security-lockdown' ), '', '' ),
			);
		}
		$https = 0 === strpos( home_url(), 'https://' );
		return Security_Headers_Audit::audit( $front['headers'], $https );
	}

	/**
	 * Builds a standard row.
	 *
	 * @param string $id          Identifier.
	 * @param string $group       Group slug.
	 * @param string $title       Title.
	 * @param string $status      pass | warn | fail | info.
	 * @param string $summary     Finding.
	 * @param string $remediation What a human should do.
	 * @param string $requires    '' | manual | server.
	 * @return array
	 */
	private static function row( $id, $group, $title, $status, $summary, $remediation, $requires ) {
		return array(
			'id'          => $id,
			'group'       => $group,
			'title'       => $title,
			'status'      => $status,
			'summary'     => $summary,
			'remediation' => $remediation,
			'requires'    => $requires,
			'deep'        => false,
		);
	}
}
