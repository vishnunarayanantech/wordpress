<?php
/**
 * Bounded audit log.
 *
 * @package WP_Security_Lockdown
 */

namespace WP_Security_Lockdown;

defined( 'ABSPATH' ) || exit;

/**
 * Records lifecycle, policy and security events.
 *
 * Properties:
 *  - Bounded: a ring buffer of at most MAX_ENTRIES (oldest entries are overwritten, never the whole log).
 *  - One write per request: entries are buffered and flushed once on `shutdown`.
 *  - No secrets: callers pass fixed event names and scalar context only; keys that look sensitive
 *    are redacted and values are truncated. Passwords, cookies and tokens must never be passed in.
 *  - Never deleted automatically on deactivation or uninstall.
 */
class Audit_Logger {

	const OPTION      = 'wp_security_lockdown_audit_log';
	const MAX_ENTRIES = 200;
	const MAX_MESSAGE = 240;
	const MAX_CONTEXT = 8;
	const MAX_VALUE   = 120;
	const LEVELS      = array( 'info', 'warning', 'error' );

	/**
	 * Entries waiting to be written.
	 *
	 * @var array[] Entries waiting to be written.
	 */
	private $buffer = array();

	/**
	 * Whether the shutdown flush has been registered.
	 *
	 * @var bool Whether the shutdown flush has been registered.
	 */
	private $flush_registered = false;

	/**
	 * Convenience wrappers.
	 *
	 * @param string $event   Machine-readable event slug.
	 * @param string $message Fixed human-readable message (never user input).
	 * @param array  $context Scalar key/value context.
	 * @return void
	 */
	public function info( $event, $message, array $context = array() ) {
		$this->log( 'info', $event, $message, $context );
	}

	/**
	 * Logs a warning.
	 *
	 * @param string $event   Event slug.
	 * @param string $message Message.
	 * @param array  $context Context.
	 * @return void
	 */
	public function warning( $event, $message, array $context = array() ) {
		$this->log( 'warning', $event, $message, $context );
	}

	/**
	 * Logs an error.
	 *
	 * @param string $event   Event slug.
	 * @param string $message Message.
	 * @param array  $context Context.
	 * @return void
	 */
	public function error( $event, $message, array $context = array() ) {
		$this->log( 'error', $event, $message, $context );
	}

	/**
	 * Queues an entry. Nothing touches the database until flush().
	 *
	 * @param string $level   info | warning | error.
	 * @param string $event   Event slug.
	 * @param string $message Message.
	 * @param array  $context Context.
	 * @return void
	 */
	public function log( $level, $event, $message, array $context = array() ) {
		if ( ! in_array( $level, self::LEVELS, true ) ) {
			$level = 'info';
		}

		$this->buffer[] = array(
			't' => time(),
			'l' => $level,
			'e' => substr( preg_replace( '/[^a-z0-9_]/', '', strtolower( (string) $event ) ), 0, 40 ),
			'm' => $this->clean_string( $message, self::MAX_MESSAGE ),
			'c' => $this->clean_context( $context ),
		);

		if ( ! $this->flush_registered ) {
			$this->flush_registered = true;
			add_action( 'shutdown', array( $this, 'flush' ), 0 );
		}
	}

	/**
	 * Writes buffered entries, keeping only the newest MAX_ENTRIES.
	 *
	 * @return void
	 */
	public function flush() {
		if ( ! $this->buffer ) {
			return;
		}

		$stored = get_option( self::OPTION, array() );
		$stored = is_array( $stored ) ? $stored : array();
		$merged = array_merge( $stored, $this->buffer );
		$limit  = $this->max_entries();
		if ( count( $merged ) > $limit ) {
			$merged = array_slice( $merged, -$limit );
		}

		$this->buffer = array();
		update_option( self::OPTION, $merged, false );
		// Never autoloaded.
	}

	/**
	 * Newest-first entries.
	 *
	 * @param int $limit Maximum number to return.
	 * @return array[]
	 */
	public function entries( $limit = 100 ) {
		$this->flush();
		$stored = get_option( self::OPTION, array() );
		if ( ! is_array( $stored ) ) {
			return array();
		}
		$entries = array();
		foreach ( $stored as $entry ) {
			if ( is_array( $entry ) ) {
				$entries[] = $this->normalize_entry( $entry );
			}
		}
		return array_slice( array_reverse( $entries ), 0, max( 1, (int) $limit ) );
	}

	/**
	 * Coerces a stored entry to the documented shape. The stored option is data that can be damaged or
	 * edited by hand, so nothing downstream may assume its types.
	 *
	 * @param array $entry Stored entry.
	 * @return array
	 */
	private function normalize_entry( array $entry ) {
		$level = isset( $entry['l'] ) && is_string( $entry['l'] ) && in_array( $entry['l'], self::LEVELS, true ) ? $entry['l'] : 'info';
		return array(
			't' => isset( $entry['t'] ) && is_numeric( $entry['t'] ) ? (int) $entry['t'] : 0,
			'l' => $level,
			'e' => isset( $entry['e'] ) && is_scalar( $entry['e'] ) ? (string) $entry['e'] : '',
			'm' => isset( $entry['m'] ) && is_scalar( $entry['m'] ) ? (string) $entry['m'] : '',
			'c' => isset( $entry['c'] ) && is_array( $entry['c'] ) ? $this->clean_context( $entry['c'] ) : array(),
		);
	}

	/**
	 * Number of stored entries (informational).
	 *
	 * @return int
	 */
	public function count() {
		$stored = get_option( self::OPTION, array() );
		return is_array( $stored ) ? count( $stored ) : 0;
	}

	/**
	 * Maximum number of retained entries. Filterable, but always clamped to a sane range.
	 *
	 * @return int
	 */
	public function max_entries() {
		/**
		 * Filters how many audit entries are retained (clamped to 50..1000).
		 *
		 * @param int $max Default 200.
		 */
		$max = (int) apply_filters( 'wp_security_lockdown_log_max_entries', self::MAX_ENTRIES );
		return max( 50, min( 1000, $max ) );
	}

	/**
	 * Reduces a string to printable ASCII-safe text of bounded length.
	 *
	 * @param mixed $value  Value.
	 * @param int   $length Maximum length.
	 * @return string
	 */
	private function clean_string( $value, $length ) {
		$value = is_scalar( $value ) ? (string) $value : '';
		$value = preg_replace( '/[\x00-\x1F\x7F]+/', ' ', $value );
		return function_exists( 'mb_substr' ) ? mb_substr( $value, 0, $length ) : substr( $value, 0, $length );
	}

	/**
	 * Keeps a small set of scalar context values and redacts sensitive-looking keys.
	 *
	 * @param array $context Raw context.
	 * @return array
	 */
	private function clean_context( array $context ) {
		$clean = array();
		foreach ( $context as $key => $value ) {
			if ( count( $clean ) >= self::MAX_CONTEXT ) {
				break;
			}
			$key = substr( preg_replace( '/[^a-z0-9_]/', '', strtolower( (string) $key ) ), 0, 30 );
			if ( '' === $key ) {
				continue;
			}
			if ( preg_match( '/pass|pwd|token|cookie|secret|nonce|auth|key|salt|hash/', $key ) ) {
				$clean[ $key ] = '[redacted]';
			} elseif ( is_bool( $value ) ) {
				$clean[ $key ] = $value;
			} elseif ( is_int( $value ) || is_float( $value ) ) {
				$clean[ $key ] = $value;
			} elseif ( is_string( $value ) ) {
				$clean[ $key ] = $this->clean_string( $value, self::MAX_VALUE );
			}
			// Arrays, objects and null are dropped on purpose.
		}
		return $clean;
	}
}
