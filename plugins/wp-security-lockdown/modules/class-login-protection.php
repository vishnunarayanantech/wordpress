<?php
/**
 * Login rate limiting and password-length policy.
 *
 * @package WP_Security_Lockdown
 */

namespace WP_Security_Lockdown\Modules;

use WP_Security_Lockdown\Abstract_Module;
use WP_Security_Lockdown\Client_IP;
use WP_Security_Lockdown\Rate_Limiter;

defined( 'ABSPATH' ) || exit;

/**
 * Controls `login_limiter` and `password_policy`.
 *
 * Login limiter
 *  - Failures are charged to a CLIENT ADDRESS (IPv6 grouped by /64), never to an account. An
 *    attacker therefore cannot lock the real administrator out by guessing their user name, and no
 *    lock is permanent: every counter and lock expires on its own.
 *  - The lock is enforced on the `authenticate` filter at priority 100. An earlier WP_Error would
 *    not stop core's credential check (which still runs and can return a valid user), so the
 *    decision has to come last. `wp_authenticate_user` at priority 1 additionally skips the
 *    password hash check for locked clients.
 *  - Attempts made while locked are not counted and a successful login does not reset the counter
 *    (otherwise an attacker holding one valid account could reset it between guesses).
 *  - The client address is REMOTE_ADDR unless trusted proxies AND a header are explicitly
 *    configured (see Client_IP). When the address demonstrably identifies a shared proxy rather
 *    than a visitor, the limiter FAILS OPEN and the dashboard says so, because locking one shared
 *    address would lock everybody out.
 *  - Recovery: wait for the lock to expire; use another network; add your address to the allowlist;
 *    or define WP_SECURITY_LOCKDOWN_DISABLE_LOGIN_LIMITER in wp-config.php (works while locked out).
 *  - Not covered, and documented as such: REST application-password failures, password-reset
 *    requests. Use fail2ban / a WAF for network-level blocking.
 *
 * Password policy: a minimum length (NIST 800-63B favours length over composition rules) enforced on
 * the profile / add-user screens, the password-reset form and the REST users endpoint. It cannot
 * stop code that calls wp_set_password() directly.
 */
class Login_Protection extends Abstract_Module {

	const LOCKED_CODE  = 'wp_security_lockdown_locked';
	const LOG_THROTTLE = 'wp_security_lockdown_lockout_log';

	/**
	 * Rate limiter, created lazily.
	 *
	 * @var Rate_Limiter|null
	 */
	private $limiter = null;

	/**
	 * Client IP resolver, created lazily.
	 *
	 * @var Client_IP|null
	 */
	private $resolver = null;

	/**
	 * Memoized per-request client assessment.
	 *
	 * @var array|null Memoized per-request client assessment.
	 */
	private $subject = null;

	/**
	 * Returns the module slug.
	 *
	 * @return string
	 */
	public function slug() {
		return 'login_protection';
	}

	/**
	 * Returns the control definitions.
	 *
	 * @return array
	 */
	public function controls() {
		return array(
			'login_limiter'   => array(
				'title'       => __( 'Login rate limiting', 'wp-security-lockdown' ),
				'description' => __( 'Temporarily blocks a client address after repeated failed logins. Never locks accounts.', 'wp-security-lockdown' ),
			),
			'password_policy' => array(
				'title'       => __( 'Minimum password length', 'wp-security-lockdown' ),
				'description' => __( 'Rejects new passwords shorter than the configured length on the profile, add-user, password-reset and REST user screens.', 'wp-security-lockdown' ),
			),
		);
	}

	/**
	 * Registers the hooks of the controls that are switched on.
	 *
	 * @return void
	 */
	public function register() {
		if ( $this->limiter_active() ) {
			add_filter( 'wp_authenticate_user', array( $this, 'check_user' ), 1 );
			add_filter( 'authenticate', array( $this, 'enforce_lock' ), 100 );
			add_action( 'wp_login_failed', array( $this, 'record_failure' ), 10, 2 );
		}
		if ( $this->plugin->settings()->control_enabled( 'password_policy' ) ) {
			add_action( 'user_profile_update_errors', array( $this, 'check_profile_password' ), 10, 3 );
			add_action( 'validate_password_reset', array( $this, 'check_reset_password' ), 10, 2 );
			add_filter( 'rest_dispatch_request', array( $this, 'check_rest_password' ), 10, 2 );
		}
	}

	/**
	 * Whether the limiter should be active (policy on and not switched off by the emergency constant).
	 *
	 * @return bool
	 */
	public function limiter_active() {
		return $this->plugin->settings()->control_enabled( 'login_limiter' ) && ! $this->kill_switch();
	}

	/**
	 * The emergency override defined in wp-config.php. Protected so tests can simulate it (a constant cannot be undefined).
	 *
	 * @return bool
	 */
	protected function kill_switch() {
		return defined( 'WP_SECURITY_LOCKDOWN_DISABLE_LOGIN_LIMITER' ) && WP_SECURITY_LOCKDOWN_DISABLE_LOGIN_LIMITER;
	}

	/**
	 * Returns the rate limiter.
	 *
	 * @return Rate_Limiter
	 */
	public function limiter() {
		if ( null === $this->limiter ) {
			$s             = $this->plugin->settings();
			$this->limiter = new Rate_Limiter(
				(int) $s->get( 'login.max_attempts', 5 ),
				(int) $s->get( 'login.window', 900 ),
				(int) $s->get( 'login.lockout', 900 )
			);
		}
		return $this->limiter;
	}

	/**
	 * Returns the client IP resolver.
	 *
	 * @return Client_IP
	 */
	public function resolver() {
		if ( null === $this->resolver ) {
			$s              = $this->plugin->settings();
			$this->resolver = new Client_IP( (array) $s->get( 'login.trusted_proxies', array() ), (string) $s->get( 'login.proxy_header', '' ) );
		}
		return $this->resolver;
	}

	/**
	 * Who is making this request, and may they be rate limited at all?
	 *
	 * @return array array( limit => bool, why => string, key => string, ip => string ).
	 */
	protected function subject() {
		if ( null !== $this->subject ) {
			return $this->subject;
		}

		$none          = array(
			'limit' => false,
			'why'   => '',
			'key'   => '',
			'ip'    => '',
		);
		$this->subject = $none;

		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			$this->subject['why'] = 'cli';
			return $this->subject;
		}

		$client = $this->resolver()->resolve( $_SERVER ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- values are validated as IP addresses inside Client_IP.
		if ( null === $client['ip'] ) {
			$this->subject['why'] = 'no_ip';
			return $this->subject;
		}
		if ( $client['degraded'] ) {
			// Many visitors share this address: punishing it would punish everyone. Fail open, loudly.
			$this->plugin->state()->note_proxy_degraded( (string) $client['reason'] );
			$this->subject['why'] = (string) $client['reason'];
			return $this->subject;
		}
		if ( Client_IP::matches_any( $client['ip'], (array) $this->plugin->settings()->get( 'login.allowlist', array() ) ) ) {
			$this->subject['why'] = 'allowlisted';
			return $this->subject;
		}

		$this->subject = array(
			'limit' => true,
			'why'   => '',
			'key'   => Client_IP::bucket_key( $client['ip'] ),
			'ip'    => $client['ip'],
		);
		return $this->subject;
	}

	/**
	 * Seconds the current client is locked for; 0 when not locked or exempt.
	 *
	 * @return int
	 */
	protected function lock_remaining() {
		$subject = $this->subject();
		return $subject['limit'] ? $this->limiter()->remaining_lock( $subject['key'] ) : 0;
	}

	/**
	 * `wp_authenticate_user`: skip the (expensive) password check for a locked client.
	 *
	 * @param \WP_User|\WP_Error $user User found by the authentication handler.
	 * @return \WP_User|\WP_Error
	 */
	public function check_user( $user ) {
		$remaining = $this->lock_remaining();
		return $remaining > 0 ? $this->locked_error( $remaining ) : $user;
	}

	/**
	 * `authenticate` at priority 100: the final word, also over a correct password.
	 *
	 * @param \WP_User|\WP_Error|null $user Result so far.
	 * @return \WP_User|\WP_Error|null
	 */
	public function enforce_lock( $user ) {
		$remaining = $this->lock_remaining();
		return $remaining > 0 ? $this->locked_error( $remaining ) : $user;
	}

	/**
	 * `wp_login_failed`: counts a failure for the client.
	 *
	 * @param string         $username Submitted login (never stored or logged: users sometimes type their password there).
	 * @param \WP_Error|null $error    The failure.
	 * @return void
	 */
	public function record_failure( $username, $error = null ) {
		unset( $username );
		if ( $error instanceof \WP_Error && in_array( self::LOCKED_CODE, $error->get_error_codes(), true ) ) {
			return;
			// Blocked attempts are not counted.
		}

		$subject = $this->subject();
		if ( ! $subject['limit'] ) {
			return;
		}
		$result = $this->limiter()->record_failure( $subject['key'] );
		if ( $result['new_lock'] ) {
			$this->log_lockout( $subject['ip'] );
		}
	}

	/**
	 * Logs a lockout at most once every five minutes so a distributed attack cannot flood the log.
	 *
	 * @param string $ip Client address (stored anonymized).
	 * @return void
	 */
	private function log_lockout( $ip ) {
		if ( false !== get_transient( self::LOG_THROTTLE ) ) {
			return;
		}
		set_transient( self::LOG_THROTTLE, 1, 5 * MINUTE_IN_SECONDS );
		$this->plugin->logger()->warning(
			'login_lockout',
			'A client was temporarily locked out after repeated failed logins (further lockouts are not logged for five minutes).',
			array( 'client' => wp_privacy_anonymize_ip( $ip ) )
		);
	}

	/**
	 * Builds the error for a locked client and sets HTTP 429 on wp-login.php.
	 *
	 * @param int $seconds Remaining lock time.
	 * @return \WP_Error
	 */
	private function locked_error( $seconds ) {
		if ( isset( $GLOBALS['pagenow'] ) && 'wp-login.php' === $GLOBALS['pagenow'] ) {
			status_header( 429 );
			// Core skips the actual header when output has already started.
			if ( ! headers_sent() ) {
				header( 'Retry-After: ' . (int) $seconds );
			}
		}
		$minutes = max( 1, (int) ceil( $seconds / 60 ) );
		return new \WP_Error(
			self::LOCKED_CODE,
			sprintf(
				/* translators: %d: minutes. */
				_n(
					'<strong>Error:</strong> Too many failed login attempts. Please try again in %d minute.',
					'<strong>Error:</strong> Too many failed login attempts. Please try again in %d minutes.',
					$minutes,
					'wp-security-lockdown'
				),
				$minutes
			)
		);
	}

	/**
	 * Returns an error message when a password is shorter than the policy, otherwise null.
	 *
	 * @param string $password Candidate password.
	 * @return string|null
	 */
	public function password_error( $password ) {
		$min = (int) $this->plugin->settings()->get( 'login.min_password_length', 0 );
		if ( $min <= 0 || ! is_string( $password ) || '' === $password ) {
			return null;
		}
		if ( mb_strlen( $password, 'UTF-8' ) >= $min ) {
			return null;
		}
		return sprintf(
			/* translators: %d: minimum number of characters. */
			__( '<strong>Error:</strong> The password must be at least %d characters long.', 'wp-security-lockdown' ),
			$min
		);
	}

	/**
	 * `user_profile_update_errors`.
	 *
	 * @param \WP_Error $errors Errors collector.
	 * @param bool      $update Whether this is an update.
	 * @param \stdClass $user   User being saved.
	 * @return void
	 */
	public function check_profile_password( $errors, $update = false, $user = null ) {
		unset( $update );
		if ( ! $errors instanceof \WP_Error || ! is_object( $user ) || empty( $user->user_pass ) ) {
			return;
		}
		$message = $this->password_error( $user->user_pass );
		if ( null !== $message ) {
			$errors->add( 'pass', $message, array( 'form-field' => 'pass1' ) );
		}
	}

	/**
	 * `validate_password_reset`.
	 *
	 * @param \WP_Error $errors Errors collector.
	 * @return void
	 */
	public function check_reset_password( $errors ) {
		if ( ! $errors instanceof \WP_Error || empty( $_POST['pass1'] ) || ! is_string( $_POST['pass1'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing -- core's reset form verifies the reset key; this only reads the candidate password.
			return;
		}
		$message = $this->password_error( wp_unslash( $_POST['pass1'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- passwords must not be altered.
		if ( null !== $message ) {
			$errors->add( 'password_too_short', $message );
		}
	}

	/**
	 * `rest_dispatch_request`: runs after the endpoint's permission check and before its callback, and honours a
	 * WP_Error result. (`rest_pre_insert_user` cannot be used: the users controller does not handle an error returned
	 * from it.)
	 *
	 * @param mixed            $dispatch_result Result so far (null = let the endpoint run).
	 * @param \WP_REST_Request $request         The request.
	 * @return mixed
	 */
	public function check_rest_password( $dispatch_result, $request = null ) {
		if ( null !== $dispatch_result || ! $request instanceof \WP_REST_Request ) {
			return $dispatch_result;
		}
		if ( ! in_array( $request->get_method(), array( 'POST', 'PUT', 'PATCH' ), true ) ) {
			return $dispatch_result;
		}
		if ( 1 !== preg_match( '#^/wp/v2/users(?:/(?:\d+|me))?$#i', untrailingslashit( $request->get_route() ) ) ) {
			return $dispatch_result;
		}
		$password = $request->get_param( 'password' );
		if ( is_string( $password ) && '' !== $password ) {
			$message = $this->password_error( $password );
			if ( null !== $message ) {
				return new \WP_Error( 'rest_user_invalid_password', wp_strip_all_tags( $message ), array( 'status' => 400 ) );
			}
		}
		return $dispatch_result;
	}

	/**
	 * Reports every control of this module.
	 *
	 * @return array
	 */
	public function report() {
		return array(
			'login_limiter'   => $this->report_limiter(),
			'password_policy' => $this->report_password_policy(),
		);
	}

	/**
	 * Reports the login limiter control.
	 *
	 * @return array
	 */
	private function report_limiter() {
		$s      = $this->plugin->settings();
		$switch = $this->kill_switch();
		$report = $this->make_report(
			'login_limiter',
			array(
				'enabled'     => $s->control_enabled( 'login_limiter' ) && ! $switch,
				'desired'     => sprintf(
					/* translators: 1: attempts, 2: minutes window, 3: minutes lockout. */
					__( 'A client address is blocked for %3$d minutes after %1$d failed logins within %2$d minutes. Accounts are never locked.', 'wp-security-lockdown' ),
					(int) $s->get( 'login.max_attempts' ),
					(int) round( $s->get( 'login.window' ) / 60 ),
					(int) round( $s->get( 'login.lockout' ) / 60 )
				),
				'enforcement' => array(
					__( 'Filters wp_authenticate_user (priority 1) and authenticate (priority 100); action wp_login_failed. Counters live in expiring, size-bounded transients. Nothing persists after deactivation.', 'wp-security-lockdown' ),
				),
			)
		);

		$report['warnings'][] = __( 'Counting is best-effort (not atomic): under heavy concurrency a few failures can be missed. It never over-counts. REST application-password failures and password-reset requests are not rate limited; use fail2ban or a WAF for network-level blocking.', 'wp-security-lockdown' );

		if ( $switch ) {
			$report['state']      = self::STATE_DISABLED;
			$report['warnings'][] = __( 'Switched off by WP_SECURITY_LOCKDOWN_DISABLE_LOGIN_LIMITER in wp-config.php (emergency override).', 'wp-security-lockdown' );
			return $report;
		}
		if ( ! $report['enabled'] ) {
			$report['state'] = self::STATE_DISABLED;
			return $report;
		}

		$attached            = $this->hooked( 'authenticate', array( $this, 'enforce_lock' ) ) && $this->hooked( 'wp_login_failed', array( $this, 'record_failure' ) );
		$report['details'][] = array(
			'label'  => 'authenticate / wp_login_failed',
			'status' => $attached ? 'ok' : 'fail',
			'text'   => $attached ? __( 'Hooks are attached.', 'wp-security-lockdown' ) : __( 'Hooks are NOT attached.', 'wp-security-lockdown' ),
		);

		$client              = $this->resolver()->resolve( $_SERVER ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- validated inside Client_IP.
		$report['details'][] = array(
			'label'  => __( 'Client address for this request', 'wp-security-lockdown' ),
			'status' => null === $client['ip'] || $client['degraded'] ? 'warn' : 'ok',
			'text'   => null === $client['ip']
				? __( 'REMOTE_ADDR is missing or invalid; the limiter cannot identify clients.', 'wp-security-lockdown' )
				: sprintf(
					/* translators: 1: IP address, 2: how it was determined. */
					__( '%1$s (%2$s)', 'wp-security-lockdown' ),
					$client['ip'],
					$client['via_proxy'] ? __( 'from the trusted proxy header', 'wp-security-lockdown' ) : __( 'REMOTE_ADDR', 'wp-security-lockdown' )
				),
		);

		$snapshot            = $this->limiter()->snapshot();
		$report['details'][] = array(
			'label'  => __( 'Tracked / locked clients now', 'wp-security-lockdown' ),
			'status' => 'info',
			'text'   => sprintf( '%d / %d', $snapshot['tracked'], $snapshot['locked'] ),
		);

		$seen     = $this->plugin->state()->get( 'proxy_degraded' );
		$recent   = isset( $seen['time'] ) && ( time() - (int) $seen['time'] ) < WEEK_IN_SECONDS;
		$degraded = $client['degraded'] || $recent;

		if ( ! $attached ) {
			$report['state']          = self::STATE_FAILED;
			$report['failure_reason'] = __( 'The login hooks are not attached in this request.', 'wp-security-lockdown' );
		} elseif ( $degraded ) {
			$report['state']          = self::STATE_PARTIAL;
			$report['failure_reason'] = 'proxy_header_unusable' === ( $client['reason'] ?? ( $seen['reason'] ?? '' ) )
				? __( 'A configured trusted proxy did not supply a usable client address header, so visitors would share one address. The limiter is NOT counting failures for those requests.', 'wp-security-lockdown' )
				: __( 'Requests arrive from a private address with forwarding headers, i.e. behind a reverse proxy that is not configured as trusted. All visitors would share one address, so the limiter is NOT counting failures. Configure your trusted proxies in the policy settings.', 'wp-security-lockdown' );
			$report['manual_action']  = __( 'Declare your reverse proxy / CDN ranges and client-IP header under Login protection.', 'wp-security-lockdown' );
		} else {
			$report['state'] = self::STATE_ENFORCED;
		}
		return $report;
	}

	/**
	 * Reports the password policy control.
	 *
	 * @return array
	 */
	private function report_password_policy() {
		$s                    = $this->plugin->settings();
		$report               = $this->make_report(
			'password_policy',
			array(
				'desired'     => sprintf(
					/* translators: %d: minimum length. */
					__( 'New passwords must be at least %d characters long.', 'wp-security-lockdown' ),
					(int) $s->get( 'login.min_password_length' )
				),
				'enforcement' => array( __( 'Action user_profile_update_errors, action validate_password_reset, filter rest_dispatch_request (users endpoint).', 'wp-security-lockdown' ) ),
			)
		);
		$report['warnings'][] = __( 'Code that calls wp_set_password() directly (imports, some membership plugins) bypasses this check. Existing passwords are not changed.', 'wp-security-lockdown' );

		if ( ! $report['enabled'] ) {
			$report['state'] = self::STATE_DISABLED;
			return $report;
		}
		$attached = $this->hooked( 'user_profile_update_errors', array( $this, 'check_profile_password' ) )
			&& $this->hooked( 'validate_password_reset', array( $this, 'check_reset_password' ) )
			&& $this->hooked( 'rest_dispatch_request', array( $this, 'check_rest_password' ) );
		if ( $attached ) {
			$report['state'] = self::STATE_ENFORCED;
		} else {
			$report['state']          = self::STATE_FAILED;
			$report['failure_reason'] = __( 'The password policy hooks are not attached in this request.', 'wp-security-lockdown' );
		}
		return $report;
	}

	/**
	 * Self-tests. No real login attempts are made: that would count against, and could lock, your own address.
	 *
	 * @param \WP_Security_Lockdown\Http_Probe|null $probe Unused.
	 * @return array
	 */
	public function verify( ?\WP_Security_Lockdown\Http_Probe $probe = null ) {
		unset( $probe );
		$results = array();
		$s       = $this->plugin->settings();

		if ( $this->limiter_active() ) {
			$clock = time();
			$test  = new Rate_Limiter(
				3,
				60,
				120,
				static function () use ( &$clock ) {
					return $clock;
				}
			);
			$key   = substr( hash( 'sha256', 'selftest' . wp_rand() . microtime() ), 0, 32 );

			$local   = array();
			$local[] = array( 0 === $test->remaining_lock( $key ), 'a fresh key is not locked' );
			$test->record_failure( $key );
			$test->record_failure( $key );
			$local[] = array( 0 === $test->remaining_lock( $key ), 'below the threshold nothing is locked' );
			$third   = $test->record_failure( $key );
			$local[] = array( $third['new_lock'] && $test->remaining_lock( $key ) > 0, 'the threshold failure creates a lock' );
			$local[] = array( ! $test->record_failure( $key )['new_lock'], 'attempts while locked do not extend the lock' );
			$clock  += 121;
			$local[] = array( 0 === $test->remaining_lock( $key ), 'the lock expires on its own' );
			$test->record_failure( $key );
			$test->clear( $key );
			$local[] = array( 0 === $test->remaining_lock( $key ), 'a key can be cleared' );

			$local[] = array( $this->hooked( 'authenticate', array( $this, 'enforce_lock' ) ), 'authenticate hook attached' );
			$local[] = array( $this->hooked( 'wp_login_failed', array( $this, 'record_failure' ) ), 'wp_login_failed hook attached' );

			$results['login_limiter'] = $this->conclude( $local, array(), false, '', self::METHOD_SELF_TEST );
			if ( Abstract_Module::VERIFIED === $results['login_limiter']['status'] ) {
				$results['login_limiter']['detail'] .= '. ' . __( 'No real login attempts were made; the counters and storage were exercised with a synthetic key.', 'wp-security-lockdown' );
			}
		}//end if

		if ( $s->control_enabled( 'password_policy' ) ) {
			$min                        = (int) $s->get( 'login.min_password_length' );
			$local                      = array(
				array( null !== $this->password_error( str_repeat( 'a', $min - 1 ) ), 'a password one character too short is rejected' ),
				array( null === $this->password_error( str_repeat( 'a', $min ) ), 'a password of the minimum length is accepted' ),
				array( $this->hooked( 'user_profile_update_errors', array( $this, 'check_profile_password' ) ), 'profile hook attached' ),
			);
			$results['password_policy'] = $this->conclude( $local, array(), false, '', self::METHOD_SELF_TEST );
		}
		return $results;
	}
}
