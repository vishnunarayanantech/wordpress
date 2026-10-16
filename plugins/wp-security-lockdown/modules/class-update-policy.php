<?php
/**
 * Security update monitoring.
 *
 * @package WP_Security_Lockdown
 */

namespace WP_Security_Lockdown\Modules;

use WP_Security_Lockdown\Abstract_Module;
use WP_Security_Lockdown\Http_Probe;
use WP_Security_Lockdown\Wp_Config_Inspector;

defined( 'ABSPATH' ) || exit;

/**
 * Control `updates` (monitor only).
 *
 * This module deliberately changes NOTHING. Patching is the most effective security control there
 * is, and silently altering an administrator's update policy (or a host's) could cause outages or
 * conflict with their own change process. So it only answers: "can security updates actually be
 * installed on this site right now, and if not, why not?"
 *
 * Checked: constants and filters that disable updates, the update cron events, WordPress.org
 * reachability settings, version-control checkouts (which make WordPress skip automatic updates),
 * whether PHP may write the WordPress files without credentials, failed background updates, and the
 * updates that are pending.
 */
class Update_Policy extends Abstract_Module {

	const FS_TRANSIENT = 'wp_security_lockdown_updates_fs';

	/**
	 * Per-request memo of the findings.
	 *
	 * @var array|null Per-request memo of the details list.
	 */
	private $details = null;

	/**
	 * Returns the module slug.
	 *
	 * @return string
	 */
	public function slug() {
		return 'update_policy';
	}

	/**
	 * Returns the control definitions.
	 *
	 * @return array
	 */
	public function controls() {
		return array(
			'updates' => array(
				'title'       => __( 'Security updates (monitored)', 'wp-security-lockdown' ),
				'description' => __( 'Never changes your update settings. Reports whether security updates can actually be installed here, what blocks them, and what is pending.', 'wp-security-lockdown' ),
			),
		);
	}

	/**
	 * Nothing to enforce, nothing to hook.
	 *
	 * @return void
	 */
	public function register() {}

	/**
	 * Control id => report (the shape Policy_Manager expects).
	 *
	 * @return array
	 */
	public function report() {
		return array( 'updates' => $this->build_report() );
	}

	/**
	 * Builds the report of this module's single control.
	 *
	 * @return array
	 */
	private function build_report() {
		$report = $this->make_report(
			'updates',
			array(
				'enabled'      => true,
				'state'        => self::STATE_MONITOR,
				'desired'      => __( 'WordPress core security releases stay enabled and able to install. Plugin and theme updates are not blocked by this plugin.', 'wp-security-lockdown' ),
				'enforcement'  => array( __( 'None by design: the plugin only observes and never alters update behaviour.', 'wp-security-lockdown' ) ),
				'persists'     => '',
				'server_level' => true,
			)
		);

		$details = $this->collect();
		$issues  = 0;
		foreach ( $details as $detail ) {
			if ( in_array( $detail['status'], array( 'warn', 'fail' ), true ) ) {
				++$issues;
			}
		}
		$report['details'] = $details;

		if ( $issues > 0 ) {
			$report['failure_reason'] = sprintf(
				/* translators: %d: number of findings. */
				_n( '%d finding limits or blocks security updates.', '%d findings limit or block security updates.', $issues, 'wp-security-lockdown' ),
				$issues
			);
			$report['manual_action'] = __( 'Review the update findings below. This plugin will not change your update policy for you.', 'wp-security-lockdown' );
		}
		return $report;
	}

	/**
	 * Refreshes the filesystem write check (it creates and removes a temporary file, so it is not run on every view).
	 *
	 * @param Http_Probe|null $probe Presence of a probe means "deep run requested".
	 * @return array Always empty: this control is monitored, not verified.
	 */
	public function verify( ?Http_Probe $probe = null ) {
		if ( $probe ) {
			$this->filesystem_check( true );
			$this->details = null;
		}
		return array();
	}

	// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- reads the effective value of core update filters; it never adds to them.
	/**
	 * Gathers every finding.
	 *
	 * @return array[] Each: label, status (ok|warn|fail|info), text.
	 */
	public function collect() {
		if ( null !== $this->details ) {
			return $this->details;
		}

		$d      = array();
		$config = new Wp_Config_Inspector();

		// 1. Switches that disable updates.
		if ( ! wp_is_file_mod_allowed( 'automatic_updater' ) ) {
			$d[] = $this->row( 'DISALLOW_FILE_MODS', 'fail', __( 'File modifications are disabled (DISALLOW_FILE_MODS or the file_mod_allowed filter). This blocks ALL core, plugin and theme updates from the dashboard and in the background. Only appropriate if updates are deployed another way.', 'wp-security-lockdown' ) );
		} else {
			$d[] = $this->row( 'DISALLOW_FILE_MODS', 'ok', __( 'Not set: updates are allowed to write files.', 'wp-security-lockdown' ) );
		}

		$disabled = defined( 'AUTOMATIC_UPDATER_DISABLED' ) && AUTOMATIC_UPDATER_DISABLED;
		if ( $disabled || apply_filters( 'automatic_updater_disabled', false ) ) {
			$d[] = $this->row( 'AUTOMATIC_UPDATER_DISABLED', 'fail', __( 'The automatic updater is disabled (constant or the automatic_updater_disabled filter). Security releases will not install on their own.', 'wp-security-lockdown' ) );
		} else {
			$d[] = $this->row( 'AUTOMATIC_UPDATER_DISABLED', 'ok', __( 'The automatic updater is not disabled.', 'wp-security-lockdown' ) );
		}

		if ( defined( 'WP_AUTO_UPDATE_CORE' ) && false === WP_AUTO_UPDATE_CORE ) {
			$d[] = $this->row( 'WP_AUTO_UPDATE_CORE', 'fail', __( 'Set to false: even minor (security and maintenance) core releases are not installed automatically.', 'wp-security-lockdown' ) );
		} elseif ( ! apply_filters( 'allow_minor_auto_core_updates', true ) ) {
			$d[] = $this->row( 'allow_minor_auto_core_updates', 'fail', __( 'A filter blocks automatic minor core updates, which carry security fixes.', 'wp-security-lockdown' ) );
		} else {
			$d[] = $this->row( 'WP_AUTO_UPDATE_CORE', 'ok', __( 'Minor core releases (security fixes) are allowed to install automatically.', 'wp-security-lockdown' ) );
		}

		$source = $config->constant( 'AUTOMATIC_UPDATER_DISABLED' );
		if ( $source['defined'] && $config->readable() ) {
			$d[] = $this->row( 'wp-config.php', 'info', __( 'wp-config.php defines AUTOMATIC_UPDATER_DISABLED, so this is an explicit administrator or host choice.', 'wp-security-lockdown' ) );
		}

		// 2. Update checks and cron.
		if ( ! has_filter( 'wp_version_check', 'wp_version_check' ) ) {
			$d[] = $this->row( 'wp_version_check', 'fail', __( 'A plugin or mu-plugin has removed the core update check callback, so WordPress cannot learn about new releases.', 'wp-security-lockdown' ) );
		}
		if ( defined( 'DISABLE_WP_CRON' ) && DISABLE_WP_CRON ) {
			$d[] = $this->row( 'DISABLE_WP_CRON', 'info', __( 'WP-Cron is disabled. Update checks only run if a system cron job calls wp-cron.php regularly.', 'wp-security-lockdown' ) );
		}
		$stale = $this->last_check_age();
		if ( null !== $stale && $stale > 2 * DAY_IN_SECONDS ) {
			$d[] = $this->row(
				__( 'Last update check', 'wp-security-lockdown' ),
				'warn',
				sprintf(
				/* translators: %s: human-readable time span. */
					__( 'WordPress last checked for core updates %s ago. Checks should run at least twice a day.', 'wp-security-lockdown' ),
					human_time_diff( time() - $stale )
				)
			);
		}
		if ( defined( 'WP_HTTP_BLOCK_EXTERNAL' ) && WP_HTTP_BLOCK_EXTERNAL && ( ! defined( 'WP_ACCESSIBLE_HOSTS' ) || false === stripos( (string) WP_ACCESSIBLE_HOSTS, 'wordpress.org' ) ) ) {
			$d[] = $this->row( 'WP_HTTP_BLOCK_EXTERNAL', 'fail', __( 'Outgoing HTTP requests are blocked and wordpress.org is not in WP_ACCESSIBLE_HOSTS, so WordPress cannot check for or download updates.', 'wp-security-lockdown' ) );
		}

		// 3. Environment restrictions that make the updater skip or fail.
		foreach ( $this->vcs_contexts() as $label => $dir ) {
			if ( $this->is_vcs_checkout( $dir ) ) {
				$d[] = $this->row(
					sprintf( /* translators: %s: core / plugins / themes. */ __( 'Version control (%s)', 'wp-security-lockdown' ), $label ),
					'warn',
					sprintf(
					/* translators: %s: update area. */
						__( 'WordPress detected a version-control checkout (.git, .svn, .hg or .bzr) around the %s directory and therefore skips AUTOMATIC updates there. Updates must be applied through your deployment process, or remove the VCS directory / decide to allow it with the automatic_updates_is_vcs_checkout filter (your choice; not changed here).', 'wp-security-lockdown' ),
						$label
					)
				);
			}
		}
		$fs = $this->filesystem_check( false );
		if ( null === $fs ) {
			$d[] = $this->row( __( 'File ownership / write access', 'wp-security-lockdown' ), 'info', __( 'Not checked yet. Run verification to test whether PHP may write the WordPress files (this creates and deletes a temporary file).', 'wp-security-lockdown' ) );
		} elseif ( 'direct' !== $fs['method'] ) {
			$d[] = $this->row(
				__( 'File ownership / write access', 'wp-security-lockdown' ),
				'fail',
				sprintf(
				/* translators: 1: filesystem method, 2: user PHP runs as, 3: owner of WordPress files. */
					__( 'WordPress would need FTP/SSH credentials to update (filesystem method "%1$s"): PHP runs as "%2$s" but the WordPress files belong to "%3$s". Automatic and one-click updates cannot run until ownership or the update process is arranged. This plugin does not change permissions.', 'wp-security-lockdown' ),
					$fs['method'],
					$fs['php_user'],
					$fs['file_owner']
				)
			);
		} else {
			$d[] = $this->row( __( 'File ownership / write access', 'wp-security-lockdown' ), 'ok', __( 'PHP can write the WordPress files directly, so updates can install without credentials.', 'wp-security-lockdown' ) );
		}

		// 4. History and backlog.
		$failed = get_site_option( 'auto_core_update_failed' );
		if ( is_array( $failed ) && $failed ) {
			$d[] = $this->row(
				__( 'Background core update', 'wp-security-lockdown' ),
				'fail',
				sprintf(
				/* translators: 1: error code, 2: yes/no. */
					__( 'A previous automatic core update failed (error code: %1$s; critical: %2$s). Until you update manually from Dashboard > Updates, automatic updates may stay disabled.', 'wp-security-lockdown' ),
					isset( $failed['error_code'] ) ? sanitize_key( (string) $failed['error_code'] ) : '?',
					! empty( $failed['critical'] ) ? __( 'yes', 'wp-security-lockdown' ) : __( 'no', 'wp-security-lockdown' )
				)
			);
		}
		$d = array_merge( $d, $this->pending_updates() );

		$this->details = $d;
		return $d;
	}
	// phpcs:enable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound

	/**
	 * Builds one finding row.
	 *
	 * @param string $label  Row label.
	 * @param string $status ok | warn | fail | info.
	 * @param string $text   Explanation.
	 * @return array
	 */
	private function row( $label, $status, $text ) {
		return array(
			'label'  => $label,
			'status' => $status,
			'text'   => $text,
		);
	}

	/**
	 * Seconds since WordPress last asked wordpress.org about core updates, or null if never.
	 *
	 * @return int|null
	 */
	private function last_check_age() {
		$core = get_site_transient( 'update_core' );
		if ( is_object( $core ) && ! empty( $core->last_checked ) ) {
			return max( 0, time() - (int) $core->last_checked );
		}
		return null;
	}

	/**
	 * Core / plugin / theme updates that are available but not installed.
	 *
	 * @return array[]
	 */
	private function pending_updates() {
		global $wp_version;
		$rows = array();

		$core = get_site_transient( 'update_core' );
		if ( is_object( $core ) && ! empty( $core->updates ) && is_array( $core->updates ) ) {
			foreach ( $core->updates as $update ) {
				if ( isset( $update->response, $update->current ) && 'upgrade' === $update->response && version_compare( (string) $update->current, (string) $wp_version, '>' ) ) {
					$minor  = $this->same_branch( (string) $update->current, (string) $wp_version );
					$rows[] = $this->row(
						__( 'WordPress core', 'wp-security-lockdown' ),
						$minor ? 'fail' : 'warn',
						sprintf(
						/* translators: 1: available version, 2: installed version, 3: explanation. */
							__( 'Version %1$s is available (installed: %2$s). %3$s', 'wp-security-lockdown' ),
							sanitize_text_field( (string) $update->current ),
							$wp_version,
							$minor ? __( 'This is a minor release of your branch: such releases carry security fixes. Install it as soon as possible.', 'wp-security-lockdown' ) : __( 'This is a new branch; schedule it after testing.', 'wp-security-lockdown' )
						)
					);
					break;
				}
			}
		}

		foreach ( array(
			'update_plugins' => __( 'Plugins', 'wp-security-lockdown' ),
			'update_themes'  => __( 'Themes', 'wp-security-lockdown' ),
		) as $transient => $label ) {
			$value = get_site_transient( $transient );
			$count = ( is_object( $value ) && ! empty( $value->response ) && is_array( $value->response ) ) ? count( $value->response ) : 0;
			if ( $count > 0 ) {
				$rows[] = $this->row(
					$label,
					'warn',
					sprintf(
					/* translators: %d: number of updates. */
						_n( '%d update is available. Plugin and theme updates frequently fix security issues.', '%d updates are available. Plugin and theme updates frequently fix security issues.', $count, 'wp-security-lockdown' ),
						$count
					)
				);
			}
		}
		return $rows;
	}

	/**
	 * Whether two versions share major.minor (a maintenance / security release).
	 *
	 * @param string $a Version.
	 * @param string $b Version.
	 * @return bool
	 */
	private function same_branch( $a, $b ) {
		$pa = explode( '.', $a );
		$pb = explode( '.', $b );
		return isset( $pa[0], $pa[1], $pb[0], $pb[1] ) && $pa[0] === $pb[0] && $pa[1] === $pb[1];
	}

	/**
	 * The directories WordPress passes to the version-control check, per update area.
	 *
	 * @return array label => path.
	 */
	private function vcs_contexts() {
		return array(
			'core'    => ABSPATH,
			'plugins' => WP_PLUGIN_DIR,
			'themes'  => get_theme_root(),
		);
	}

	/**
	 * Uses WordPress's own detection (including its filter and open_basedir handling).
	 *
	 * @param string $context Directory.
	 * @return bool
	 */
	private function is_vcs_checkout( $context ) {
		if ( ! class_exists( 'WP_Automatic_Updater' ) ) {
			require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
		}
		$updater = new \WP_Automatic_Updater();
		return (bool) $updater->is_vcs_checkout( $context );
	}

	/**
	 * Whether PHP can write the plugin directory without credentials, using WordPress's own test.
	 * That test creates and deletes a temporary file, so the answer is cached for an hour.
	 *
	 * @param bool $refresh Run the test now.
	 * @return array|null array( method, php_user, file_owner ) or null when never checked.
	 */
	public function filesystem_check( $refresh ) {
		$cached = get_transient( self::FS_TRANSIENT );
		if ( ! $refresh ) {
			return is_array( $cached ) ? $cached : null;
		}

		if ( ! function_exists( 'get_filesystem_method' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}
		$method = get_filesystem_method( array(), WP_PLUGIN_DIR );
		$result = array(
			'method'     => sanitize_key( (string) $method ),
			'php_user'   => $this->user_name( function_exists( 'posix_geteuid' ) ? posix_geteuid() : null ),
			'file_owner' => $this->user_name( @fileowner( ABSPATH . 'wp-settings.php' ) ), // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- may be unreadable on hardened hosts.
		);
		set_transient( self::FS_TRANSIENT, $result, HOUR_IN_SECONDS );
		return $result;
	}

	/**
	 * Resolves a numeric user id to a user name.
	 *
	 * @param int|false|null $uid Numeric user id.
	 * @return string User name, or "unknown".
	 */
	private function user_name( $uid ) {
		if ( null === $uid || false === $uid ) {
			return 'unknown';
		}
		if ( function_exists( 'posix_getpwuid' ) ) {
			$info = posix_getpwuid( (int) $uid );
			if ( is_array( $info ) && isset( $info['name'] ) ) {
				return sanitize_user( $info['name'], true );
			}
		}
		return 'uid ' . (int) $uid;
	}
}
