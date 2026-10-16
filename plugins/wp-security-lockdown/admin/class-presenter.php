<?php
/**
 * Display helpers for the dashboard templates.
 *
 * @package WP_Security_Lockdown
 */

namespace WP_Security_Lockdown\Admin;

use WP_Security_Lockdown\Abstract_Module;
use WP_Security_Lockdown\Policy_Manager;

defined( 'ABSPATH' ) || exit;

/**
 * Turns statuses into words, icons and CSS classes. Colour is never the only signal: every badge
 * carries an icon character and a text label.
 */
class Presenter {

	/**
	 * Badge for a control's display status.
	 *
	 * @param string $status Policy_Manager status constant.
	 * @return string Escaped HTML.
	 */
	public static function status_badge( $status ) {
		$map   = array(
			Policy_Manager::VERIFIED_HTTP  => array( 'ok', "\u{2714}", __( 'Verified over HTTP', 'wp-security-lockdown' ) ),
			Policy_Manager::VERIFIED_LOCAL => array( 'ok', "\u{2714}", __( 'Verified in PHP', 'wp-security-lockdown' ) ),
			Policy_Manager::MONITOR_OK     => array( 'ok', "\u{2714}", __( 'No findings', 'wp-security-lockdown' ) ),
			Policy_Manager::UNVERIFIED     => array( 'warn', '?', __( 'Not verified', 'wp-security-lockdown' ) ),
			Policy_Manager::PARTIAL        => array( 'warn', '!', __( 'Partially enforced', 'wp-security-lockdown' ) ),
			Policy_Manager::MONITOR_WARN   => array( 'warn', '!', __( 'Findings', 'wp-security-lockdown' ) ),
			Policy_Manager::NOT_WORKING    => array( 'bad', "\u{2716}", __( 'Not working', 'wp-security-lockdown' ) ),
			Policy_Manager::FAILED         => array( 'bad', "\u{2716}", __( 'Failed', 'wp-security-lockdown' ) ),
			Policy_Manager::DISABLED       => array( 'off', "\u{2013}", __( 'Disabled', 'wp-security-lockdown' ) ),
		);
		$entry = isset( $map[ $status ] ) ? $map[ $status ] : array( 'off', '?', __( 'Unknown', 'wp-security-lockdown' ) );
		return sprintf( '<span class="wpsl-badge wpsl-%1$s"><span aria-hidden="true">%2$s</span> %3$s</span>', esc_attr( $entry[0] ), esc_html( $entry[1] ), esc_html( $entry[2] ) );
	}

	/**
	 * Badge for a diagnostics row.
	 *
	 * @param string $status pass | warn | fail | info.
	 * @return string Escaped HTML.
	 */
	public static function check_badge( $status ) {
		$map   = array(
			'pass' => array( 'ok', "\u{2714}", __( 'OK', 'wp-security-lockdown' ) ),
			'warn' => array( 'warn', '!', __( 'Warning', 'wp-security-lockdown' ) ),
			'fail' => array( 'bad', "\u{2716}", __( 'Problem', 'wp-security-lockdown' ) ),
			'info' => array( 'info', 'i', __( 'Info', 'wp-security-lockdown' ) ),
			'ok'   => array( 'ok', "\u{2714}", __( 'OK', 'wp-security-lockdown' ) ),
		);
		$entry = isset( $map[ $status ] ) ? $map[ $status ] : $map['info'];
		return sprintf( '<span class="wpsl-badge wpsl-%1$s"><span aria-hidden="true">%2$s</span> %3$s</span>', esc_attr( $entry[0] ), esc_html( $entry[1] ), esc_html( $entry[2] ) );
	}

	/**
	 * Tag for findings that need a person or the server.
	 *
	 * @param string $requires '' | manual | server.
	 * @return string Escaped HTML (possibly empty).
	 */
	public static function requires_tag( $requires ) {
		if ( 'manual' === $requires ) {
			return '<span class="wpsl-tag">' . esc_html__( 'Manual action', 'wp-security-lockdown' ) . '</span>';
		}
		if ( 'server' === $requires ) {
			return '<span class="wpsl-tag">' . esc_html__( 'Server-level', 'wp-security-lockdown' ) . '</span>';
		}
		return '';
	}

	/**
	 * Plain-language label of how something was verified.
	 *
	 * @param string $method Verification method.
	 * @return string
	 */
	public static function method_label( $method ) {
		switch ( $method ) {
			case Abstract_Module::METHOD_HTTP:
				return __( 'real HTTP request(s)', 'wp-security-lockdown' );
			case Abstract_Module::METHOD_SELF_TEST:
				return __( 'self-test of the logic and storage', 'wp-security-lockdown' );
			case Abstract_Module::METHOD_IN_PROCESS:
				return __( 'checks inside PHP', 'wp-security-lockdown' );
			default:
				return __( 'not tested', 'wp-security-lockdown' );
		}
	}

	/**
	 * "5 minutes ago (2026-10-16 11:51)" or "never".
	 *
	 * @param int $timestamp Unix time.
	 * @return string
	 */
	public static function when( $timestamp ) {
		$timestamp = (int) $timestamp;
		if ( $timestamp <= 0 ) {
			return __( 'never', 'wp-security-lockdown' );
		}
		return sprintf(
			/* translators: 1: human time difference, 2: exact date and time. */
			__( '%1$s ago (%2$s)', 'wp-security-lockdown' ),
			human_time_diff( $timestamp ),
			wp_date( 'Y-m-d H:i', $timestamp )
		);
	}

	/**
	 * Renders an option value for the rollback table.
	 *
	 * @param mixed $value Value.
	 * @param bool  $absent Whether the option does not exist.
	 * @return string Escaped text.
	 */
	public static function option_value( $value, $absent = false ) {
		if ( $absent ) {
			return '<em>' . esc_html__( '(not set)', 'wp-security-lockdown' ) . '</em>';
		}
		if ( ! is_scalar( $value ) ) {
			return '<em>' . esc_html__( '(complex)', 'wp-security-lockdown' ) . '</em>';
		}
		return '<code>' . esc_html( '' === (string) $value ? '(empty)' : substr( (string) $value, 0, 60 ) ) . '</code>';
	}

	/**
	 * Compact "key=value" rendering of an audit entry's context.
	 *
	 * @param array $context Context.
	 * @return string Escaped text.
	 */
	public static function context( $context ) {
		if ( ! is_array( $context ) || ! $context ) {
			return '';
		}
		$parts = array();
		foreach ( $context as $key => $value ) {
			$parts[] = esc_html( (string) $key ) . '=' . esc_html( is_bool( $value ) ? ( $value ? 'true' : 'false' ) : ( is_scalar( $value ) ? (string) $value : '' ) );
		}
		return implode( ', ', $parts );
	}
}
