<?php
/**
 * Security header audit.
 *
 * @package WP_Security_Lockdown
 */

namespace WP_Security_Lockdown;

defined( 'ABSPATH' ) || exit;

/**
 * Compares the response headers of the front page with widely accepted baselines and explains the
 * compatibility risk of each recommendation.
 *
 * The plugin deliberately does NOT send these headers itself. Headers set by PHP never reach static
 * files, CDNs or error pages, can conflict with headers the web server already sends, and a wrong
 * Content-Security-Policy can silently break scripts, payment flows or the admin. Set them at the
 * web server / CDN, where they apply to every response, using the snippets shown on the dashboard.
 */
class Security_Headers_Audit {

	/**
	 * Audits response headers against the baselines.
	 *
	 * @param array $headers  Response headers with lower-case names.
	 * @param bool  $is_https Whether the audited URL is served over HTTPS.
	 * @return array[] Rows: id, group, title, status (pass|warn|info), summary, remediation, requires, snippet (key => directive).
	 */
	public static function audit( array $headers, $is_https ) {
		$rows = array();
		$h    = static function ( $name ) use ( $headers ) {
			return isset( $headers[ $name ] ) ? trim( (string) $headers[ $name ] ) : '';
		};

		// X-Content-Type-Options.
		$value  = strtolower( $h( 'x-content-type-options' ) );
		$rows[] = self::row(
			'x-content-type-options',
			'nosniff' === $value ? 'pass' : 'warn',
			'' === $value ? __( 'Missing.', 'wp-security-lockdown' ) : sprintf( /* translators: %s: header value. */ __( 'Present: %s', 'wp-security-lockdown' ), self::short( $value ) ),
			__( 'Send "X-Content-Type-Options: nosniff". Compatibility: safe for practically every site; it only matters for files served with a wrong MIME type.', 'wp-security-lockdown' ),
			array( 'X-Content-Type-Options' => 'nosniff' )
		);

		// Clickjacking: X-Frame-Options or CSP frame-ancestors.
		$xfo    = $h( 'x-frame-options' );
		$csp    = $h( 'content-security-policy' );
		$framed = '' !== $xfo || false !== stripos( $csp, 'frame-ancestors' );
		$rows[] = self::row(
			'clickjacking',
			$framed ? 'pass' : 'warn',
			$framed ? __( 'Framing is restricted.', 'wp-security-lockdown' ) : __( 'Nothing stops other sites from embedding your pages in a frame.', 'wp-security-lockdown' ),
			__( 'Send "X-Frame-Options: SAMEORIGIN" (or the CSP directive frame-ancestors \'self\'). Compatibility: this stops legitimate embedding of your pages by OTHER sites (partner portals, page builders\' external previews); allow those origins with frame-ancestors instead. WordPress already sends SAMEORIGIN on wp-login.php and wp-admin.', 'wp-security-lockdown' ),
			array( 'X-Frame-Options' => 'SAMEORIGIN' )
		);

		// Referrer-Policy.
		$value  = strtolower( $h( 'referrer-policy' ) );
		$weak   = in_array( $value, array( 'unsafe-url', 'no-referrer-when-downgrade', 'origin-when-cross-origin' ), true );
		$rows[] = self::row(
			'referrer-policy',
			'' === $value ? 'info' : ( $weak ? 'warn' : 'pass' ),
			'' === $value ? __( 'Missing (browsers fall back to their own default).', 'wp-security-lockdown' ) : sprintf( /* translators: %s: header value. */ __( 'Present: %s', 'wp-security-lockdown' ), self::short( $value ) ),
			__( 'Send "Referrer-Policy: strict-origin-when-cross-origin". Compatibility: this is the modern browser default, so it is safe; only analytics or affiliate tools that need the full referring URL on cross-site links may notice.', 'wp-security-lockdown' ),
			array( 'Referrer-Policy' => 'strict-origin-when-cross-origin' )
		);

		// HSTS.
		$value = strtolower( $h( 'strict-transport-security' ) );
		if ( ! $is_https ) {
			$rows[] = self::row(
				'strict-transport-security',
				'info',
				__( 'Not applicable: the site is not being served over HTTPS here.', 'wp-security-lockdown' ),
				__( 'First serve the whole site over HTTPS. Only then send "Strict-Transport-Security: max-age=31536000". Do NOT add includeSubDomains or preload until every subdomain serves valid HTTPS: both are hard to undo.', 'wp-security-lockdown' ),
				array()
			);
		} else {
			$age    = preg_match( '/max-age=(\d+)/', $value, $m ) ? (int) $m[1] : 0;
			$rows[] = self::row(
				'strict-transport-security',
				$age >= 15552000 ? 'pass' : 'warn',
				'' === $value ? __( 'Missing.', 'wp-security-lockdown' ) : sprintf( /* translators: %s: header value. */ __( 'Present: %s', 'wp-security-lockdown' ), self::short( $value ) ),
				__( 'Send "Strict-Transport-Security: max-age=31536000". Compatibility: browsers will refuse plain HTTP for the whole period, so make sure HTTPS works everywhere first. Avoid includeSubDomains / preload unless every subdomain is HTTPS-only.', 'wp-security-lockdown' ),
				array( 'Strict-Transport-Security' => 'max-age=31536000' )
			);
		}

		// Permissions-Policy.
		$value  = $h( 'permissions-policy' );
		$rows[] = self::row(
			'permissions-policy',
			'' !== $value ? 'pass' : 'info',
			'' === $value ? __( 'Missing (optional hardening).', 'wp-security-lockdown' ) : sprintf( /* translators: %s: header value. */ __( 'Present: %s', 'wp-security-lockdown' ), self::short( $value ) ),
			__( 'Optionally send "Permissions-Policy: camera=(), microphone=(), geolocation=()". Compatibility: add payment=(self) if you take payments on the site, and widen geolocation / camera for embedded maps or video-call widgets that need them.', 'wp-security-lockdown' ),
			array( 'Permissions-Policy' => 'camera=(), microphone=(), geolocation=()' )
		);

		// Content-Security-Policy: never recommend blind enforcement.
		$enforced = '' !== $csp;
		$report   = '' !== $h( 'content-security-policy-report-only' );
		$rows[]   = self::row(
			'content-security-policy',
			$enforced ? 'pass' : 'info',
			$enforced ? __( 'A Content-Security-Policy is present. This audit does not judge its contents.', 'wp-security-lockdown' ) : ( $report ? __( 'Only a Report-Only policy is present (a sensible first step).', 'wp-security-lockdown' ) : __( 'No Content-Security-Policy.', 'wp-security-lockdown' ) ),
			__( 'A CSP is the strongest browser-side defence against cross-site scripting, but it must not be switched on blindly: WordPress core, themes and plugins use inline scripts and styles, and payment, analytics, font and embed providers must be allowlisted. Start with "Content-Security-Policy-Report-Only", collect the violation reports, fix or allow what is legitimate, and only then enforce. The block editor and wp-admin need a looser policy than the public site.', 'wp-security-lockdown' ),
			array()
		);

		// Software disclosure.
		$server  = $h( 'server' );
		$rows[]  = self::row(
			'server',
			'' !== $server && preg_match( '/\d/', $server ) ? 'warn' : 'pass',
			'' === $server ? __( 'No Server header.', 'wp-security-lockdown' ) : sprintf( /* translators: %s: header value. */ __( 'Server: %s', 'wp-security-lockdown' ), self::short( $server ) ),
			__( 'Hide software versions: Apache "ServerTokens Prod" and "ServerSignature Off", or nginx "server_tokens off;". This only removes free reconnaissance; patching is what protects you.', 'wp-security-lockdown' ),
			array(),
			true
		);
		$powered = $h( 'x-powered-by' );
		$rows[]  = self::row(
			'x-powered-by',
			'' === $powered ? 'pass' : 'warn',
			'' === $powered ? __( 'No X-Powered-By header.', 'wp-security-lockdown' ) : sprintf( /* translators: %s: header value. */ __( 'X-Powered-By: %s', 'wp-security-lockdown' ), self::short( $powered ) ),
			__( 'Set "expose_php = Off" in php.ini (or "header_remove(\'X-Powered-By\')" at the web server).', 'wp-security-lockdown' ),
			array(),
			true
		);

		return $rows;
	}

	/**
	 * Copy-paste web server configuration for the directives that are safe to recommend.
	 *
	 * @param array[] $rows Output of audit().
	 * @return array array( apache => string, nginx => string ).
	 */
	public static function snippets( array $rows ) {
		$directives = array();
		foreach ( $rows as $row ) {
			if ( 'pass' !== $row['status'] && ! empty( $row['snippet'] ) && 'header_permissions-policy' !== $row['id'] ) {
				$directives = array_merge( $directives, $row['snippet'] );
			}
		}
		if ( ! $directives ) {
			return array(
				'apache' => '',
				'nginx'  => '',
			);
		}

		$apache = "<IfModule mod_headers.c>\n";
		$nginx  = '';
		foreach ( $directives as $name => $value ) {
			$apache .= sprintf( "\tHeader always set %s \"%s\"\n", $name, $value );
			$nginx  .= sprintf( "add_header %s \"%s\" always;\n", $name, $value );
		}
		$apache .= '</IfModule>';
		return array(
			'apache' => $apache,
			'nginx'  => $nginx,
		);
	}

	/**
	 * Builds one audit row.
	 *
	 * @param string $id          Identifier.
	 * @param string $status      pass | warn | info.
	 * @param string $summary     What was found.
	 * @param string $remediation Recommendation and compatibility note.
	 * @param array  $snippet     Header => value for the generated server snippet.
	 * @param bool   $server_info Whether this is a software-disclosure row (shown differently).
	 * @return array
	 */
	private static function row( $id, $status, $summary, $remediation, array $snippet, $server_info = false ) {
		$titles = array(
			'x-content-type-options'    => 'X-Content-Type-Options',
			'clickjacking'              => __( 'Clickjacking protection (X-Frame-Options / frame-ancestors)', 'wp-security-lockdown' ),
			'referrer-policy'           => 'Referrer-Policy',
			'strict-transport-security' => 'Strict-Transport-Security (HSTS)',
			'permissions-policy'        => 'Permissions-Policy',
			'content-security-policy'   => 'Content-Security-Policy',
			'server'                    => __( 'Server software disclosure (Server header)', 'wp-security-lockdown' ),
			'x-powered-by'              => __( 'Software disclosure (X-Powered-By header)', 'wp-security-lockdown' ),
		);
		return array(
			'id'          => 'header_' . $id,
			'group'       => 'headers',
			'title'       => isset( $titles[ $id ] ) ? $titles[ $id ] : $id,
			'status'      => $status,
			'summary'     => $summary,
			'remediation' => 'pass' === $status ? '' : $remediation,
			'requires'    => 'pass' === $status ? '' : 'server',
			'snippet'     => $server_info ? array() : $snippet,
		);
	}

	/**
	 * Truncates a header value for display.
	 *
	 * @param string $value Header value.
	 * @return string
	 */
	private static function short( $value ) {
		return substr( preg_replace( '/[^\x20-\x7E]/', '?', $value ), 0, 100 );
	}
}
