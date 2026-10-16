<?php
/**
 * File editor protection and filesystem diagnostics.
 *
 * @package WP_Security_Lockdown
 */

namespace WP_Security_Lockdown\Modules;

use WP_Security_Lockdown\Abstract_Module;
use WP_Security_Lockdown\Http_Probe;
use WP_Security_Lockdown\Wp_Config_Inspector;

defined( 'ABSPATH' ) || exit;

/**
 * Control `file_editor` plus read-only filesystem diagnostics.
 *
 * File editor: DISALLOW_FILE_EDIT removes the `edit_files`, `edit_plugins` and `edit_themes`
 * capabilities. The plugin defines the constant at load time when nothing else has, and ALSO denies
 * those capabilities through `map_meta_cap`, so the editor stays off even when wp-config.php
 * explicitly sets the constant to false. wp-config.php is never read for anything but constant
 * names, and never written. DISALLOW_FILE_MODS is deliberately not touched: it would block updates.
 *
 * Diagnostics never change permissions or ownership (a PHP process doing that on its own is both
 * unreliable and dangerous). They report what a human or the host has to fix.
 */
class File_Security extends Abstract_Module {

	const EDITOR_CAPS = array( 'edit_files', 'edit_plugins', 'edit_themes' );

	const SCAN_LIMIT = 5000;

	/**
	 * Returns the module slug.
	 *
	 * @return string
	 */
	public function slug() {
		return 'file_security';
	}

	/**
	 * Returns the control definitions.
	 *
	 * @return array
	 */
	public function controls() {
		return array(
			'file_editor' => array(
				'title'       => __( 'Dashboard file editor', 'wp-security-lockdown' ),
				'description' => __( 'Removes the theme and plugin code editors from the dashboard, so an account takeover cannot edit PHP files from the browser.', 'wp-security-lockdown' ),
			),
		);
	}

	/**
	 * Defines DISALLOW_FILE_EDIT when nothing has and denies the editor capabilities.
	 *
	 * @return void
	 */
	public function register() {
		if ( ! $this->plugin->settings()->control_enabled( 'file_editor' ) ) {
			return;
		}
		if ( ! defined( 'DISALLOW_FILE_EDIT' ) ) {
			define( 'DISALLOW_FILE_EDIT', true ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound -- the core constant is the whole point.
		}
		add_filter( 'map_meta_cap', array( $this, 'deny_editor_caps' ), 10, 2 );
	}

	/**
	 * `map_meta_cap`: nobody may use the built-in code editors.
	 *
	 * @param string[] $caps Required primitive capabilities.
	 * @param string   $cap  The capability being checked.
	 * @return string[]
	 */
	public function deny_editor_caps( $caps, $cap = '' ) {
		return in_array( $cap, self::EDITOR_CAPS, true ) ? array( 'do_not_allow' ) : $caps;
	}

	/**
	 * Control id => report (the shape Policy_Manager expects).
	 *
	 * @return array
	 */
	public function report() {
		return array( 'file_editor' => $this->build_report() );
	}

	/**
	 * Builds the report of this module's single control.
	 *
	 * @return array
	 */
	private function build_report() {
		$config = new Wp_Config_Inspector();
		$report = $this->make_report(
			'file_editor',
			array(
				'desired'      => __( 'edit_files, edit_plugins and edit_themes are denied to every user.', 'wp-security-lockdown' ),
				'enforcement'  => array(
					__( 'Constant DISALLOW_FILE_EDIT defined at plugin load when not already defined, plus a map_meta_cap filter. Both stop when the plugin is deactivated.', 'wp-security-lockdown' ),
				),
				'server_level' => false,
			)
		);
		if ( ! $report['enabled'] ) {
			$report['state'] = self::STATE_DISABLED;
			return $report;
		}

		$in_config = $config->constant( 'DISALLOW_FILE_EDIT' );
		if ( ! $config->readable() ) {
			$report['details'][] = array(
				'label'  => 'wp-config.php',
				'status' => 'info',
				'text'   => __( 'wp-config.php is not readable by PHP (a good sign on hardened hosts), so it cannot be inspected. Runtime state is used instead.', 'wp-security-lockdown' ),
			);
		} elseif ( $in_config['defined'] && true === $in_config['value'] ) {
			$report['details'][] = array(
				'label'  => 'wp-config.php',
				'status' => 'ok',
				'text'   => __( 'wp-config.php already sets DISALLOW_FILE_EDIT to true. The protection does not depend on this plugin.', 'wp-security-lockdown' ),
			);
		} elseif ( $in_config['defined'] && false === $in_config['value'] ) {
			$report['details'][]  = array(
				'label'  => 'wp-config.php',
				'status' => 'warn',
				'text'   => __( 'wp-config.php sets DISALLOW_FILE_EDIT to false. The plugin still blocks the editor through a capability filter, but the setting contradicts the policy; change it to true.', 'wp-security-lockdown' ),
			);
			$report['warnings'][] = __( 'wp-config.php sets DISALLOW_FILE_EDIT to false. The editor is blocked only while this plugin is active.', 'wp-security-lockdown' );
		} elseif ( $in_config['defined'] ) {
			$report['details'][] = array(
				'label'  => 'wp-config.php',
				'status' => 'info',
				'text'   => __( 'wp-config.php defines DISALLOW_FILE_EDIT with a computed value that cannot be read statically.', 'wp-security-lockdown' ),
			);
		} else {
			$report['details'][] = array(
				'label'  => 'wp-config.php',
				'status' => 'info',
				'text'   => __( 'wp-config.php does not define DISALLOW_FILE_EDIT, so the editor is blocked only while this plugin is active. For a protection that survives deactivating the plugin, add this line yourself (the plugin never edits wp-config.php): define( \'DISALLOW_FILE_EDIT\', true );', 'wp-security-lockdown' ),
			);
		}//end if

		$attached            = $this->hooked( 'map_meta_cap', array( $this, 'deny_editor_caps' ) );
		$report['details'][] = array(
			'label'  => 'map_meta_cap',
			'status' => $attached ? 'ok' : 'fail',
			'text'   => $attached ? __( 'Capability filter is attached.', 'wp-security-lockdown' ) : __( 'Capability filter is NOT attached.', 'wp-security-lockdown' ),
		);
		$report['details'][] = array(
			'label'  => 'DISALLOW_FILE_MODS',
			'status' => 'info',
			'text'   => __( 'Not touched by this plugin: it would also block updates and plugin installs.', 'wp-security-lockdown' ),
		);

		if ( $attached ) {
			$report['state'] = self::STATE_ENFORCED;
		} else {
			$report['state']          = self::STATE_FAILED;
			$report['failure_reason'] = __( 'The capability filter is not attached in this request.', 'wp-security-lockdown' );
		}
		return $report;
	}

	/**
	 * Verifies that the editor capabilities resolve to do_not_allow.
	 *
	 * @param Http_Probe|null $probe Unused.
	 * @return array
	 */
	public function verify( ?Http_Probe $probe = null ) {
		unset( $probe );
		if ( ! $this->plugin->settings()->control_enabled( 'file_editor' ) ) {
			return array();
		}
		// A real administrator id is not needed: the mapping does not depend on the user.
		$user_id = get_current_user_id() ? get_current_user_id() : 1;
		$local   = array();
		foreach ( self::EDITOR_CAPS as $cap ) {
			$local[] = array( in_array( 'do_not_allow', map_meta_cap( $cap, $user_id ), true ), sprintf( 'map_meta_cap( %s ) resolves to do_not_allow', $cap ) );
		}
		if ( is_user_logged_in() ) {
			$local[] = array( ! current_user_can( 'edit_plugins' ) && ! current_user_can( 'edit_themes' ), 'the current user cannot use the plugin or theme editor' );
		}
		return array( 'file_editor' => $this->conclude( $local, array(), false, '' ) );
	}

	/* ===================================================================== diagnostics */

	/**
	 * Read-only filesystem checks.
	 *
	 * @param bool $deep Include the uploads scan (bounded, but touches many directory entries).
	 * @return array[] Check rows (see Health_Check::row()).
	 */
	public function diagnostics( $deep ) {
		$rows   = array();
		$rows[] = $this->check_wp_config_permissions();
		$rows[] = $this->check_directory_permissions();
		$rows[] = $this->check_core_writable();
		if ( $deep ) {
			$rows[] = $this->check_uploads();
		}
		return $rows;
	}

	/**
	 * Checks that wp-config.php is not world-readable or world-writable.
	 *
	 * @return array
	 */
	private function check_wp_config_permissions() {
		$config = new Wp_Config_Inspector();
		$path   = $config->locate();
		$title  = __( 'wp-config.php permissions', 'wp-security-lockdown' );

		if ( null === $path ) {
			return $this->row( 'wp_config_permissions', $title, 'info', __( 'wp-config.php could not be located.', 'wp-security-lockdown' ), '', 'manual' );
		}
		if ( $this->is_windows() ) {
			return $this->row( 'wp_config_permissions', $title, 'info', __( 'POSIX permissions do not apply on Windows; use NTFS ACLs.', 'wp-security-lockdown' ), '', 'server' );
		}
		$mode = $this->mode( $path );
		if ( null === $mode ) {
			return $this->row( 'wp_config_permissions', $title, 'info', __( 'The permissions could not be read.', 'wp-security-lockdown' ), '', 'manual' );
		}
		$octal = sprintf( '%04o', $mode );
		$fix   = __( 'Run as the file owner: chmod 640 wp-config.php (or 600), owned by the deploy user with the web server group as group.', 'wp-security-lockdown' );

		if ( $mode & 0002 ) {
			/* translators: %s: octal mode. */
			return $this->row( 'wp_config_permissions', $title, 'fail', sprintf( __( 'wp-config.php is world-writable (mode %s). Anyone on the server can change your database credentials.', 'wp-security-lockdown' ), $octal ), $fix, 'server' );
		}
		if ( $mode & 0004 ) {
			/* translators: %s: octal mode. */
			return $this->row( 'wp_config_permissions', $title, 'fail', sprintf( __( 'wp-config.php is readable by every local user (mode %s). On shared hosting this exposes the database password.', 'wp-security-lockdown' ), $octal ), $fix, 'server' );
		}
		if ( $mode & 0020 ) {
			/* translators: %s: octal mode. */
			return $this->row( 'wp_config_permissions', $title, 'warn', sprintf( __( 'wp-config.php is writable by its group (mode %s). Make it read-only for the web server unless you need otherwise.', 'wp-security-lockdown' ), $octal ), $fix, 'server' );
		}
		/* translators: %s: octal mode. */
		return $this->row( 'wp_config_permissions', $title, 'pass', sprintf( __( 'wp-config.php is not world-readable or world-writable (mode %s).', 'wp-security-lockdown' ), $octal ), '', '' );
	}

	/**
	 * Checks for world-writable WordPress directories.
	 *
	 * @return array
	 */
	private function check_directory_permissions() {
		$title = __( 'Directory permissions', 'wp-security-lockdown' );
		if ( $this->is_windows() ) {
			return $this->row( 'directory_permissions', $title, 'info', __( 'POSIX permissions do not apply on Windows.', 'wp-security-lockdown' ), '', 'server' );
		}

		$uploads = wp_upload_dir( null, false );
		$paths   = array(
			'WordPress root'     => untrailingslashit( ABSPATH ),
			'wp-content'         => WP_CONTENT_DIR,
			'wp-content/plugins' => WP_PLUGIN_DIR,
			'wp-content/themes'  => get_theme_root(),
		);
		if ( ! empty( $uploads['basedir'] ) ) {
			$paths['uploads'] = $uploads['basedir'];
		}

		$bad = array();
		foreach ( $paths as $label => $path ) {
			$mode = is_dir( $path ) ? $this->mode( $path ) : null;
			if ( null !== $mode && ( $mode & 0002 ) ) {
				$bad[] = sprintf( '%s (%04o)', $label, $mode );
			}
		}
		if ( $bad ) {
			return $this->row(
				'directory_permissions',
				$title,
				'fail',
				/* translators: %s: list of directories with their octal modes. */
				sprintf( __( 'World-writable directories: %s. Any local user or compromised service can plant files there.', 'wp-security-lockdown' ), implode( ', ', $bad ) ),
				__( 'Typical fix, run as the file owner: find . -type d -perm -0002 -exec chmod 755 {} + (review first; uploads usually needs group-write, not world-write).', 'wp-security-lockdown' ),
				'server'
			);
		}
		return $this->row( 'directory_permissions', $title, 'pass', __( 'None of the WordPress root, wp-content, plugins, themes or uploads directories is world-writable.', 'wp-security-lockdown' ), '', '' );
	}

	/**
	 * Informational: whether the web server user can alter WordPress core. Both answers are a trade-off.
	 *
	 * @return array
	 */
	private function check_core_writable() {
		$title    = __( 'WordPress core files writable by PHP', 'wp-security-lockdown' );
		$writable = is_writable( ABSPATH . WPINC ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- a read-only probe; WP_Filesystem would need credentials.
		if ( $writable ) {
			return $this->row(
				'core_writable',
				$title,
				'info',
				__( 'PHP can modify WordPress core files. That is what allows automatic updates, but it also means a PHP-level compromise can alter core. If you deploy updates another way, make core read-only for the web server user.', 'wp-security-lockdown' ),
				'',
				'server'
			);
		}
		return $this->row(
			'core_writable',
			$title,
			'info',
			__( 'PHP cannot modify WordPress core files (good against tampering). The consequence is that WordPress cannot update itself: apply updates through your own process, or WordPress will keep asking for FTP credentials.', 'wp-security-lockdown' ),
			'',
			'server'
		);
	}

	/**
	 * Bounded scan of the uploads directory for executable files, plus a passive look for server rules.
	 *
	 * @return array
	 */
	private function check_uploads() {
		$title   = __( 'Executable files and PHP execution in uploads', 'wp-security-lockdown' );
		$uploads = wp_upload_dir( null, false );
		$base    = ! empty( $uploads['basedir'] ) ? $uploads['basedir'] : '';
		$server  = __( 'The plugin cannot enforce this. Configure the web server so PHP never runs inside the uploads directory: Apache `<Directory "…/uploads"> php_admin_flag engine off </Directory>` (or `RemoveHandler .php .phtml .phar` / `Require all denied` for `\.(php|phtml|phar)`), or nginx `location ~* ^/wp-content/uploads/.*\.(php|phtml|phar)$ { deny all; }`.', 'wp-security-lockdown' );

		if ( '' === $base || ! is_dir( $base ) ) {
			return $this->row( 'uploads_exec', $title, 'info', __( 'The uploads directory does not exist yet, so there is nothing to scan. Configure the web server rule below before the first upload.', 'wp-security-lockdown' ), $server, 'server' );
		}

		$found   = array();
		$scanned = 0;
		$capped  = false;
		try {
			$iterator = new \RecursiveIteratorIterator(
				new \RecursiveDirectoryIterator( $base, \FilesystemIterator::SKIP_DOTS ),
				\RecursiveIteratorIterator::LEAVES_ONLY,
				\RecursiveIteratorIterator::CATCH_GET_CHILD
			);
			$iterator->setMaxDepth( 8 );
			foreach ( $iterator as $file ) {
				if ( ++$scanned > self::SCAN_LIMIT ) {
					$capped = true;
					break;
				}
				if ( preg_match( '/\.(php[0-9]?|phtml|pht|phps|phar)(\.|$)/i', $file->getFilename() ) && count( $found ) < 10 ) {
					$found[] = ltrim( str_replace( $base, '', $file->getPathname() ), '/\\' );
				}
			}
		} catch ( \Exception $e ) {
			return $this->row( 'uploads_exec', $title, 'info', __( 'The uploads directory could not be scanned (unreadable entries).', 'wp-security-lockdown' ), $server, 'server' );
		}

		$htaccess = $this->has_apache_php_rules( $base );
		$note     = $htaccess
			? __( 'An Apache .htaccess in uploads contains rules that look like they restrict PHP (heuristic only; nginx and server-level rules cannot be seen from PHP).', 'wp-security-lockdown' )
			: __( 'No server rule restricting PHP execution in uploads could be detected from PHP. That does not prove there is none (it may live in the main server configuration).', 'wp-security-lockdown' );

		if ( $found ) {
			return $this->row(
				'uploads_exec',
				$title,
				'fail',
				sprintf(
					/* translators: 1: list of file names, 2: note. */
					__( 'Executable-looking files exist in uploads: %1$s. Uploads should only hold media. Review them; if you did not put them there, treat the site as compromised. %2$s', 'wp-security-lockdown' ),
					implode( ', ', $found ),
					$note
				),
				$server,
				'server'
			);
		}
		return $this->row(
			'uploads_exec',
			$title,
			$htaccess ? 'pass' : 'warn',
			sprintf(
				/* translators: 1: number of entries scanned, 2: note. */
				__( 'No executable-looking files found (%1$d entries scanned%3$s). %2$s', 'wp-security-lockdown' ),
				min( $scanned, self::SCAN_LIMIT ),
				$note,
				$capped ? __( ', scan limit reached', 'wp-security-lockdown' ) : ''
			),
			$htaccess ? '' : $server,
			$htaccess ? '' : 'server'
		);
	}

	/**
	 * Passive, heuristic look at an Apache .htaccess in the uploads directory.
	 *
	 * @param string $base Uploads base directory.
	 * @return bool
	 */
	private function has_apache_php_rules( $base ) {
		$file = trailingslashit( $base ) . '.htaccess';
		if ( ! is_readable( $file ) || filesize( $file ) > 8192 ) {
			return false;
		}
		$content = file_get_contents( $file ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local file, read-only.
		return is_string( $content ) && 1 === preg_match( '/php_(admin_)?flag\s+engine\s+off|RemoveHandler|SetHandler\s+none|Require\s+all\s+denied|Deny\s+from\s+all/i', $content );
	}

	/**
	 * Whether POSIX permissions do not apply (Windows).
	 *
	 * @return bool
	 */
	private function is_windows() {
		return DIRECTORY_SEPARATOR === '\\';
	}

	/**
	 * Permission bits (0777 mask) of a path, or null.
	 *
	 * @param string $path Path.
	 * @return int|null
	 */
	private function mode( $path ) {
		$perms = @fileperms( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- unreadable paths simply yield "unknown".
		return false === $perms ? null : ( $perms & 0777 );
	}

	/**
	 * Builds a diagnostics row.
	 *
	 * @param string $id          Identifier.
	 * @param string $title       Title.
	 * @param string $status      pass | warn | fail | info.
	 * @param string $summary     What was found.
	 * @param string $remediation What to do.
	 * @param string $requires    '' | 'manual' | 'server'.
	 * @return array
	 */
	private function row( $id, $title, $status, $summary, $remediation, $requires ) {
		return array(
			'id'          => $id,
			'group'       => 'files',
			'title'       => $title,
			'status'      => $status,
			'summary'     => $summary,
			'remediation' => $remediation,
			'requires'    => $requires,
		);
	}
}
