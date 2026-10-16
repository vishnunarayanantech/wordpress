<?php
/**
 * Read-only inspection of wp-config.php.
 *
 * @package WP_Security_Lockdown
 */

namespace WP_Security_Lockdown;

defined( 'ABSPATH' ) || exit;

/**
 * Answers "does wp-config.php define constant X, and to what boolean?" without ever modifying the file.
 *
 * Only a fixed allowlist of non-secret constants can be asked about, and only the existence of a
 * definition plus its literal value (a boolean, small number or short mode string) is returned.
 * Database credentials, salts and every other line of the file are never exposed, logged or displayed.
 */
class Wp_Config_Inspector {

	const MAX_BYTES = 524288;

	/** Constants this class is willing to report on. */
	const INSPECTABLE = array(
		'DISALLOW_FILE_EDIT',
		'DISALLOW_FILE_MODS',
		'AUTOMATIC_UPDATER_DISABLED',
		'WP_AUTO_UPDATE_CORE',
		'WP_DEBUG',
		'WP_DEBUG_LOG',
		'WP_DEBUG_DISPLAY',
		'FORCE_SSL_ADMIN',
		'DISABLE_WP_CRON',
		'WP_HTTP_BLOCK_EXTERNAL',
		'WP_ENVIRONMENT_TYPE',
	);

	/**
	 * Explicit path (tests) or null to locate the file like WordPress does.
	 *
	 * @var string|null Explicit path (tests) or null to locate it like WordPress does.
	 */
	private $path;

	/**
	 * Parsed definitions: name => array( defined, literal, value ).
	 *
	 * @var array|null Parsed definitions: name => array( literal => bool, value => mixed ).
	 */
	private $parsed = null;

	/**
	 * Explicit path (tests) or null to locate the file like WordPress does.
	 *
	 * @param string|null $path Absolute path to a config file, or null for the site's own.
	 */
	public function __construct( $path = null ) {
		$this->path = $path;
	}

	/**
	 * Locates wp-config.php exactly where wp-load.php looks for it.
	 *
	 * @return string|null
	 */
	public function locate() {
		if ( null !== $this->path ) {
			return is_file( $this->path ) ? $this->path : null;
		}
		if ( is_file( ABSPATH . 'wp-config.php' ) ) {
			return ABSPATH . 'wp-config.php';
		}
		$parent = dirname( ABSPATH ) . '/wp-config.php';
		if ( is_file( $parent ) && ! is_file( dirname( ABSPATH ) . '/wp-settings.php' ) ) {
			return $parent;
		}
		return null;
	}

	/**
	 * Whether PHP is allowed to read the file (it often is not on hardened hosts).
	 *
	 * @return bool
	 */
	public function readable() {
		$path = $this->locate();
		return null !== $path && is_readable( $path );
	}

	/**
	 * Reports on one allowlisted constant.
	 *
	 * @param string $name Constant name.
	 * @return array {
	 *     @type bool $defined Whether wp-config.php contains a define() for it.
	 *     @type bool $literal Whether the value is a plain true/false/number/string literal.
	 *     @type mixed $value  The literal value for booleans, otherwise null.
	 * }
	 */
	public function constant( $name ) {
		$none = array(
			'defined' => false,
			'literal' => false,
			'value'   => null,
		);
		if ( ! in_array( $name, self::INSPECTABLE, true ) ) {
			return $none;
			// Anything outside the allowlist is invisible to callers.
		}
		$parsed = $this->parse();
		return isset( $parsed[ $name ] ) ? $parsed[ $name ] : $none;
	}

	/**
	 * Parses define( 'NAME', value ) calls for the allowlisted names.
	 *
	 * @return array
	 */
	private function parse() {
		if ( null !== $this->parsed ) {
			return $this->parsed;
		}
		$this->parsed = array();

		$path = $this->locate();
		if ( null === $path || ! is_readable( $path ) || filesize( $path ) > self::MAX_BYTES ) {
			return $this->parsed;
		}
		$source = file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local file, read-only.
		if ( ! is_string( $source ) || '' === $source ) {
			return $this->parsed;
		}

		$tokens = token_get_all( $source );
		$tokens = array_values(
			array_filter(
				$tokens,
				static function ( $token ) {
					return ! is_array( $token ) || ! in_array( $token[0], array( T_WHITESPACE, T_COMMENT, T_DOC_COMMENT ), true );
				}
			)
		);

		$count = count( $tokens );
		for ( $i = 0; $i < $count - 3; $i++ ) {
			// define ( 'NAME' ,   (also matches \define on PHP 8, where it is a single name token).
			if ( ! is_array( $tokens[ $i ] ) || ! in_array( strtolower( $tokens[ $i ][1] ), array( 'define', '\\define' ), true ) ) {
				continue;
			}
			if ( '(' !== $tokens[ $i + 1 ] || ! is_array( $tokens[ $i + 2 ] ) || T_CONSTANT_ENCAPSED_STRING !== $tokens[ $i + 2 ][0] || ',' !== $tokens[ $i + 3 ] ) {
				continue;
			}
			$name = trim( $tokens[ $i + 2 ][1], '\'"' );
			if ( ! in_array( $name, self::INSPECTABLE, true ) ) {
				continue;
			}
			$this->parsed[ $name ] = $this->read_value( $tokens, $i + 4 );
		}
		return $this->parsed;
	}

	/**
	 * Interprets the value argument of a define() call when it is a simple literal.
	 *
	 * @param array $tokens Significant tokens.
	 * @param int   $at     Index of the first token of the value.
	 * @return array
	 */
	private function read_value( array $tokens, $at ) {
		$result = array(
			'defined' => true,
			'literal' => false,
			'value'   => null,
		);
		$token  = isset( $tokens[ $at ] ) ? $tokens[ $at ] : null;
		$next   = isset( $tokens[ $at + 1 ] ) ? $tokens[ $at + 1 ] : null;

		// The value must be a lone token followed by `)` or `,`, otherwise it is an expression.
		if ( ! is_array( $token ) || ( ')' !== $next && ',' !== $next ) ) {
			return $result;
		}
		if ( T_STRING === $token[0] ) {
			$word = strtolower( $token[1] );
			if ( 'true' === $word || 'false' === $word ) {
				$result['literal'] = true;
				$result['value']   = ( 'true' === $word );
			}
		} elseif ( T_LNUMBER === $token[0] ) {
			$result['literal'] = true;
			$result['value']   = ( 0 !== (int) $token[1] );
		} elseif ( T_CONSTANT_ENCAPSED_STRING === $token[0] ) {
			$result['literal'] = true;
			$result['value']   = trim( $token[1], '\'"' ) !== '' ? trim( $token[1], '\'"' ) : null;
		}
		return $result;
	}
}
