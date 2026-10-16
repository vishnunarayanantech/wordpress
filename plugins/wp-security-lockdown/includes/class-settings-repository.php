<?php
/**
 * Policy settings: schema, defaults and strict sanitization.
 *
 * @package WP_Security_Lockdown
 */

namespace WP_Security_Lockdown;

defined( 'ABSPATH' ) || exit;

/**
 * Reads and writes the administrator-configured policy (`wp_security_lockdown_settings`).
 *
 * Stored data is never trusted: every read goes through the same sanitizer as every write, so a
 * corrupted or hand-edited option cannot put the plugin into an undefined state.
 */
class Settings_Repository {

	const OPTION = 'wp_security_lockdown_settings';
	const SCHEMA = 1;

	const REST_MODES = array( 'off', 'restricted', 'dashboard_only' );

	/** Client IP header => the $_SERVER key that carries it. Only these may be configured. */
	const PROXY_HEADERS = array(
		'X-Forwarded-For'  => 'HTTP_X_FORWARDED_FOR',
		'X-Real-IP'        => 'HTTP_X_REAL_IP',
		'CF-Connecting-IP' => 'HTTP_CF_CONNECTING_IP',
		'True-Client-IP'   => 'HTTP_TRUE_CLIENT_IP',
		'Fastly-Client-IP' => 'HTTP_FASTLY_CLIENT_IP',
	);

	/** Core namespaces that back wp-admin. They can never be made available to anonymous visitors. */
	const PROTECTED_NAMESPACES = array( 'wp/v2', 'wp-site-health/v1', 'wp-block-editor/v1', 'wp-abilities/v1', 'batch/v1' );

	const MAX_LIST_ENTRIES = 50;

	/**
	 * Setting that switches each control on/off. `off` is the value that disables it.
	 * Controls without an entry (xmlrpc, updates, file diagnostics) have no off switch.
	 */
	const CONTROL_FLAGS = array(
		'comments'           => array( 'comments.enabled', false ),
		'rest_api'           => array( 'rest.mode', 'off' ),
		'login_limiter'      => array( 'login.limiter', false ),
		'login_errors'       => array( 'login.generic_errors', false ),
		'author_enumeration' => array( 'disclosure.author_enumeration', false ),
		'version_exposure'   => array( 'disclosure.version', false ),
		'discovery'          => array( 'disclosure.discovery', false ),
		'error_display'      => array( 'disclosure.error_display', false ),
		'file_editor'        => array( 'files.file_editor', false ),
	);

	/**
	 * Per-request cache of the sanitized settings.
	 *
	 * @var array|null Per-request cache of the sanitized settings.
	 */
	private $cache = null;

	/**
	 * Memo of enabled_controls( all() ), dropped together with the cache.
	 *
	 * @var array|null Memo of enabled_controls( all() ), dropped together with the cache.
	 */
	private $enabled = null;

	/**
	 * Registers cache invalidation. The option is plain data, so no capability logic lives here.
	 */
	public function __construct() {
		foreach ( array( 'add_option_', 'update_option_', 'delete_option_' ) as $prefix ) {
			add_action( $prefix . self::OPTION, array( $this, 'flush_cache' ) );
		}
	}

	/**
	 * Default policy: the secure baseline described in readme.txt.
	 *
	 * @return array
	 */
	public static function defaults() {
		return array(
			'schema'     => self::SCHEMA,
			'comments'   => array(
				'enabled' => true,
			),
			'xmlrpc'     => array(
				'mode' => 'block',
		// block | allow (pingback methods are removed in both).
			),
			'rest'       => array(
				'mode'                 => 'restricted',
				'public_namespaces'    => array(),
				'dashboard_namespaces' => array(),
			),
			'login'      => array(
				'limiter'             => true,
				'max_attempts'        => 5,
				'window'              => 900,
				'lockout'             => 900,
				'allowlist'           => array(),
				'trusted_proxies'     => array(),
				'proxy_header'        => '',
				'generic_errors'      => true,
				'min_password_length' => 12,
			),
			'disclosure' => array(
				'author_enumeration' => true,
				'version'            => true,
				'discovery'          => true,
				'error_display'      => true,
			),
			'files'      => array(
				'file_editor' => true,
			),
			'lifecycle'  => array(
				'rollback_on_deactivation' => false,
			),
		);
	}

	/**
	 * Drops the per-request cache.
	 *
	 * @return void
	 */
	public function flush_cache() {
		$this->cache   = null;
		$this->enabled = null;
	}

	/**
	 * Returns the full, sanitized settings.
	 *
	 * @return array
	 */
	public function all() {
		if ( null === $this->cache ) {
			$stored      = get_option( self::OPTION, array() );
			$this->cache = $this->sanitize( is_array( $stored ) ? $stored : array(), self::defaults() );
		}
		return $this->cache;
	}

	/**
	 * Reads one value with a dotted path, e.g. `login.max_attempts`.
	 *
	 * @param string $path    Section.key.
	 * @param mixed  $fallback Returned when the path does not exist.
	 * @return mixed
	 */
	public function get( $path, $fallback = null ) {
		$node = $this->all();
		foreach ( explode( '.', $path ) as $segment ) {
			if ( ! is_array( $node ) || ! array_key_exists( $segment, $node ) ) {
				return $fallback;
			}
			$node = $node[ $segment ];
		}
		return $node;
	}

	/**
	 * Whether the administrator has switched a control on.
	 *
	 * @param string $control Control identifier.
	 * @return bool
	 */
	public function control_enabled( $control ) {
		if ( null === $this->enabled ) {
			$this->enabled = $this->enabled_controls( $this->all() );
		}
		return isset( $this->enabled[ $control ] ) ? $this->enabled[ $control ] : true;
		// Controls without an off switch are always on (xmlrpc, updates).
	}

	/**
	 * Which switchable controls are on in a given (sanitized) settings array.
	 *
	 * @param array $settings Sanitized settings.
	 * @return array control id => bool.
	 */
	public function enabled_controls( array $settings ) {
		$map = array();
		foreach ( self::CONTROL_FLAGS as $control => $flag ) {
			list( $section, $key ) = explode( '.', $flag[0], 2 );
			$map[ $control ]       = isset( $settings[ $section ][ $key ] ) ? $flag[1] !== $settings[ $section ][ $key ] : true;
		}
		$map['password_policy'] = isset( $settings['login']['min_password_length'] ) && (int) $settings['login']['min_password_length'] > 0;
		return $map;
	}

	/**
	 * Stable fingerprint of the active policy, used to detect stale verification results.
	 *
	 * @return string
	 */
	public function fingerprint() {
		return substr( md5( (string) wp_json_encode( $this->all() ) ), 0, 12 );
	}

	/**
	 * Merges a partial update over the stored settings and saves it.
	 *
	 * @param array $partial Section => key => value pairs. Unknown keys are dropped.
	 * @return string[] Dotted paths whose value changed.
	 */
	public function update( array $partial ) {
		$before = $this->all();
		$merged = $this->sanitize( $this->merge_recursive_distinct( $before, $partial ), $before );

		$changed = $this->diff_paths( $before, $merged );
		if ( $changed ) {
			// update_option() on a missing option takes the "add" path, which does not fire update_option_{option}
			// (the hook that hands persistent settings back or takes them over). Create it first.
			if ( false === get_option( self::OPTION ) ) {
				add_option( self::OPTION, $before, '', true );
			}
			update_option( self::OPTION, $merged, true );
			$this->flush_cache();
		}
		return $changed;
	}

	/**
	 * Switches one control off (used by the rollback, which hands the control back to the administrator).
	 *
	 * @param string $control Control identifier.
	 * @return bool True when a setting was changed.
	 */
	public function disable_control( $control ) {
		if ( ! isset( self::CONTROL_FLAGS[ $control ] ) ) {
			return false;
		}
		list( $path, $off_value ) = self::CONTROL_FLAGS[ $control ];
		list( $section, $key )    = explode( '.', $path, 2 );
		return (bool) $this->update( array( $section => array( $key => $off_value ) ) );
	}

	/**
	 * Settings API sanitize callback (also runs on every update_option() of this option).
	 *
	 * @param mixed $input Raw submitted value.
	 * @return array
	 */
	public function sanitize_for_settings_api( $input ) {
		$notices = array();
		$result  = $this->sanitize( is_array( $input ) ? $input : array(), $this->all(), $notices );

		if ( function_exists( 'add_settings_error' ) ) {
			foreach ( $notices as $notice ) {
				add_settings_error( self::OPTION, 'wp_security_lockdown_input', $notice, 'warning' );
			}
		}
		return $result;
	}

	/**
	 * Validates a raw settings array against the schema.
	 *
	 * Missing keys fall back to `$base`; present keys are coerced to the expected type and range.
	 * Anything that is not part of the schema is discarded.
	 *
	 * @param array      $input   Raw input.
	 * @param array      $base    Values used for keys absent from $input.
	 * @param array|null $notices Optional collector for messages about dropped input.
	 * @return array
	 */
	public function sanitize( array $input, array $base, &$notices = null ) {
		$notices  = array();
		$defaults = self::defaults();
		$base     = $this->fill_missing( $base, $defaults );
		$out      = array( 'schema' => self::SCHEMA );

		$pick = static function ( $section, $key ) use ( $input, $base ) {
			if ( isset( $input[ $section ] ) && is_array( $input[ $section ] ) && array_key_exists( $key, $input[ $section ] ) ) {
				return $input[ $section ][ $key ];
			}
			return $base[ $section ][ $key ];
		};

		$out['comments']['enabled'] = self::to_bool( $pick( 'comments', 'enabled' ) );

		$mode                  = $pick( 'xmlrpc', 'mode' );
		$out['xmlrpc']['mode'] = in_array( $mode, array( 'block', 'allow' ), true ) ? $mode : 'block';

		$mode                                = $pick( 'rest', 'mode' );
		$out['rest']['mode']                 = in_array( $mode, self::REST_MODES, true ) ? $mode : 'restricted';
		$out['rest']['public_namespaces']    = $this->sanitize_namespaces( $pick( 'rest', 'public_namespaces' ), true, $notices );
		$out['rest']['dashboard_namespaces'] = $this->sanitize_namespaces( $pick( 'rest', 'dashboard_namespaces' ), false, $notices );

		$out['login'] = array(
			'limiter'             => self::to_bool( $pick( 'login', 'limiter' ) ),
			'max_attempts'        => self::clamp_int( $pick( 'login', 'max_attempts' ), 3, 20, 5 ),
			'window'              => self::clamp_int( $pick( 'login', 'window' ), 60, DAY_IN_SECONDS, 900 ),
			'lockout'             => self::clamp_int( $pick( 'login', 'lockout' ), 60, DAY_IN_SECONDS, 900 ),
			'allowlist'           => $this->sanitize_ip_list( $pick( 'login', 'allowlist' ), 'allowlist', $notices ),
			'trusted_proxies'     => $this->sanitize_ip_list( $pick( 'login', 'trusted_proxies' ), 'trusted proxy', $notices ),
			'proxy_header'        => '',
			'generic_errors'      => self::to_bool( $pick( 'login', 'generic_errors' ) ),
			'min_password_length' => $this->sanitize_min_password_length( $pick( 'login', 'min_password_length' ) ),
		);

		$header = $pick( 'login', 'proxy_header' );
		if ( is_string( $header ) && isset( self::PROXY_HEADERS[ $header ] ) ) {
			$out['login']['proxy_header'] = $header;
		}
		if ( '' !== $out['login']['proxy_header'] && ! $out['login']['trusted_proxies'] ) {
			// A forwarded-for header is only ever honoured for explicitly trusted proxies.
			$out['login']['proxy_header'] = '';
			$notices[]                    = __( 'The client IP header was ignored because no trusted proxy was configured. Forwarded headers are never trusted without an explicit proxy list.', 'wp-security-lockdown' );
		}

		foreach ( array( 'author_enumeration', 'version', 'discovery', 'error_display' ) as $key ) {
			$out['disclosure'][ $key ] = self::to_bool( $pick( 'disclosure', $key ) );
		}
		$out['files']['file_editor']                  = self::to_bool( $pick( 'files', 'file_editor' ) );
		$out['lifecycle']['rollback_on_deactivation'] = self::to_bool( $pick( 'lifecycle', 'rollback_on_deactivation' ) );

		return $out;
	}

	/**
	 * Coerces checkbox-style input to a boolean.
	 *
	 * @param mixed $value Raw value.
	 * @return bool
	 */
	public static function to_bool( $value ) {
		if ( is_string( $value ) ) {
			return in_array( strtolower( trim( $value ) ), array( '1', 'true', 'on', 'yes' ), true );
		}
		return (bool) $value;
	}

	/**
	 * Clamps a numeric input into an inclusive range.
	 *
	 * @param mixed $value   Raw value.
	 * @param int   $min     Minimum.
	 * @param int   $max     Maximum.
	 * @param int   $fallback Used when the value is not numeric.
	 * @return int
	 */
	public static function clamp_int( $value, $min, $max, $fallback ) {
		if ( ! is_numeric( $value ) ) {
			return $fallback;
		}
		return (int) max( $min, min( $max, (int) $value ) );
	}

	/**
	 * Minimum password length: 0 switches the policy off, otherwise 8..64.
	 *
	 * @param mixed $value Raw value.
	 * @return int
	 */
	private function sanitize_min_password_length( $value ) {
		if ( ! is_numeric( $value ) ) {
			return 12;
		}
		$value = (int) $value;
		return $value <= 0 ? 0 : (int) max( 8, min( 64, $value ) );
	}

	/**
	 * Parses a list of IP addresses / CIDR ranges from an array or a free-text field.
	 *
	 * @param mixed    $raw     Array or newline/comma separated string.
	 * @param string   $label   Used in messages.
	 * @param string[] $notices Collector for dropped entries.
	 * @return string[]
	 */
	private function sanitize_ip_list( $raw, $label, array &$notices ) {
		$list = array();
		foreach ( $this->split_list( $raw ) as $entry ) {
			$normalized = Client_IP::normalize_entry( $entry );
			if ( false === $normalized ) {
				/* translators: 1: list name (allowlist / trusted proxy), 2: rejected value. */
				$notices[] = sprintf( __( 'Ignored invalid %1$s entry: %2$s', 'wp-security-lockdown' ), $label, $this->printable( $entry ) );
				continue;
			}
			$list[ $normalized ] = $normalized;
			if ( count( $list ) >= self::MAX_LIST_ENTRIES ) {
				break;
			}
		}
		return array_values( $list );
	}

	/**
	 * Parses a list of REST namespaces such as `contact-form-7/v1`.
	 *
	 * @param mixed    $raw          Array or newline/comma separated string.
	 * @param bool     $public_list  True for the anonymous allowlist, which refuses core admin namespaces.
	 * @param string[] $notices      Collector for dropped entries.
	 * @return string[]
	 */
	private function sanitize_namespaces( $raw, $public_list, array &$notices ) {
		$list = array();
		foreach ( $this->split_list( $raw ) as $entry ) {
			$entry = strtolower( trim( $entry, " \t\n\r\0\x0B/" ) );
			if ( ! preg_match( '#^[a-z0-9][a-z0-9_.-]*(/[a-z0-9][a-z0-9_.-]*){0,2}$#', $entry ) ) {
				/* translators: %s: rejected value. */
				$notices[] = sprintf( __( 'Ignored invalid REST namespace: %s', 'wp-security-lockdown' ), $this->printable( $entry ) );
				continue;
			}
			if ( $public_list && in_array( $entry, self::PROTECTED_NAMESPACES, true ) ) {
				/* translators: %s: rejected namespace. */
				$notices[] = sprintf( __( 'The core namespace %s cannot be made public. Use REST mode "Off" if you really need an open REST API.', 'wp-security-lockdown' ), $entry );
				continue;
			}
			$list[ $entry ] = $entry;
			if ( count( $list ) >= self::MAX_LIST_ENTRIES ) {
				break;
			}
		}
		return array_values( $list );
	}

	/**
	 * Splits array or free-text input into trimmed, non-empty strings.
	 *
	 * @param mixed $raw Raw value.
	 * @return string[]
	 */
	private function split_list( $raw ) {
		if ( is_array( $raw ) ) {
			$raw = implode( "\n", array_filter( $raw, 'is_scalar' ) );
		}
		if ( ! is_string( $raw ) ) {
			return array();
		}
		$parts = preg_split( '/[\s,]+/', $raw, -1, PREG_SPLIT_NO_EMPTY );
		return is_array( $parts ) ? $parts : array();
	}

	/**
	 * Shortens, strips control characters from and HTML-escapes a value before it is echoed in a notice.
	 * WordPress prints settings errors as raw HTML, so anything user-supplied must already be escaped.
	 *
	 * @param string $value Raw value.
	 * @return string
	 */
	private function printable( $value ) {
		return esc_html( substr( preg_replace( '/[^\x20-\x7E]/', '?', (string) $value ), 0, 60 ) );
	}

	/**
	 * Fills keys missing from `$base` with defaults so that sanitize() never reads an undefined index.
	 *
	 * @param array $base     Candidate base values.
	 * @param array $defaults Default values.
	 * @return array
	 */
	private function fill_missing( array $base, array $defaults ) {
		foreach ( $defaults as $section => $values ) {
			if ( ! is_array( $values ) ) {
				continue;
			}
			if ( ! isset( $base[ $section ] ) || ! is_array( $base[ $section ] ) ) {
				$base[ $section ] = array();
			}
			$base[ $section ] = $base[ $section ] + $values;
		}
		return $base;
	}

	/**
	 * Merges $override into $base, replacing (not appending to) list values.
	 *
	 * @param array $base     Base array.
	 * @param array $override Overriding array.
	 * @return array
	 */
	private function merge_recursive_distinct( array $base, array $override ) {
		foreach ( $override as $key => $value ) {
			if ( is_array( $value ) && isset( $base[ $key ] ) && is_array( $base[ $key ] ) && $this->is_assoc( $value ) ) {
				$base[ $key ] = $this->merge_recursive_distinct( $base[ $key ], $value );
			} else {
				$base[ $key ] = $value;
			}
		}
		return $base;
	}

	/**
	 * Whether an array has string keys (a map) rather than being a list.
	 *
	 * @param array $value Array to test.
	 * @return bool
	 */
	private function is_assoc( array $value ) {
		return $value && array_keys( $value ) !== range( 0, count( $value ) - 1 );
	}

	/**
	 * Lists the dotted paths whose values differ between two settings arrays.
	 *
	 * @param array  $a      First array.
	 * @param array  $b      Second array.
	 * @param string $prefix Path prefix for recursion.
	 * @return string[]
	 */
	private function diff_paths( array $a, array $b, $prefix = '' ) {
		$paths = array();
		foreach ( array_unique( array_merge( array_keys( $a ), array_keys( $b ) ) ) as $key ) {
			$path = '' === $prefix ? (string) $key : $prefix . '.' . $key;
			$av   = isset( $a[ $key ] ) ? $a[ $key ] : null;
			$bv   = isset( $b[ $key ] ) ? $b[ $key ] : null;
			if ( is_array( $av ) && is_array( $bv ) && $this->is_assoc( $av ) && $this->is_assoc( $bv ) ) {
				$paths = array_merge( $paths, $this->diff_paths( $av, $bv, $path ) );
			} elseif ( $av !== $bv ) {
				$paths[] = $path;
			}
		}
		return $paths;
	}
}
