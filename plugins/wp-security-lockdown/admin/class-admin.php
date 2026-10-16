<?php
/**
 * Administration screen.
 *
 * @package WP_Security_Lockdown
 */

namespace WP_Security_Lockdown\Admin;

use WP_Security_Lockdown\Activator;
use WP_Security_Lockdown\Http_Probe;
use WP_Security_Lockdown\Plugin;
use WP_Security_Lockdown\Rate_Limiter;
use WP_Security_Lockdown\Settings_Repository;

defined( 'ABSPATH' ) || exit;

/**
 * Dashboard: status, controls, checks, settings (Settings API), audit log, rollback.
 *
 * Security model for every state-changing request:
 *  1. It must be an HTTP POST (nothing changes on a GET, so a link or image cannot trigger it).
 *  2. The user must have the `manage_options` capability.
 *  3. A nonce specific to the action must be valid. A nonce only proves the request came from a
 *     page this user loaded; it is never treated as authorization on its own.
 * Settings are saved through the Settings API (options.php), which applies the same capability and
 * nonce checks, and every value is sanitized by Settings_Repository::sanitize().
 * Output is escaped for its context; messages shown after a redirect come from a fixed table, never
 * from request parameters.
 */
class Admin {

	const SLUG       = 'wp-security-lockdown';
	const CAPABILITY = 'manage_options';
	const TABS       = array( 'overview', 'controls', 'checks', 'settings', 'audit', 'rollback' );

	/** Admin-post action => handler method. */
	const ACTIONS = array(
		'wp_security_lockdown_verify'         => 'handle_verify',
		'wp_security_lockdown_apply'          => 'handle_apply',
		'wp_security_lockdown_rollback'       => 'handle_rollback',
		'wp_security_lockdown_clear_lockouts' => 'handle_clear_lockouts',
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
	 * Registers the menu, settings fields, assets and admin-post handlers.
	 *
	 * @return void
	 */
	public function register() {
		add_action( 'admin_menu', array( $this, 'add_menu' ) );
		add_action( 'admin_init', array( $this, 'register_settings_ui' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue' ) );
		add_action( 'admin_notices', array( $this, 'activation_notice' ) );
		add_filter( 'plugin_action_links_' . plugin_basename( WP_SECURITY_LOCKDOWN_FILE ), array( $this, 'action_links' ) );

		foreach ( self::ACTIONS as $action => $method ) {
			add_action( 'admin_post_' . $action, array( $this, $method ) );
		}
	}

	/**
	 * Adds the dashboard under Settings.
	 *
	 * @return void
	 */
	public function add_menu() {
		add_options_page(
			__( 'WP Security Lockdown', 'wp-security-lockdown' ),
			__( 'Security Lockdown', 'wp-security-lockdown' ),
			self::CAPABILITY,
			self::SLUG,
			array( $this, 'render' )
		);
	}

	/**
	 * Adds a Dashboard link to the plugin row.
	 *
	 * @param string[] $links Existing plugin row links.
	 * @return string[]
	 */
	public function action_links( $links ) {
		array_unshift( $links, '<a href="' . esc_url( self::url() ) . '">' . esc_html__( 'Dashboard', 'wp-security-lockdown' ) . '</a>' );
		return $links;
	}

	/**
	 * Builds the URL of a dashboard tab.
	 *
	 * @param string $tab  Tab slug.
	 * @param array  $args Extra query args.
	 * @return string
	 */
	public static function url( $tab = 'overview', array $args = array() ) {
		return add_query_arg(
			array_merge(
				array(
					'page' => self::SLUG,
					'tab'  => $tab,
				),
				$args
			),
			admin_url( 'options-general.php' )
		);
	}

	/**
	 * Loads the stylesheet on the dashboard page only.
	 *
	 * @param string $hook Admin page hook suffix.
	 * @return void
	 */
	public function enqueue( $hook ) {
		if ( 'settings_page_' . self::SLUG !== $hook ) {
			return;
		}
		wp_enqueue_style( 'wp-security-lockdown-admin', plugins_url( 'admin/assets/admin.css', WP_SECURITY_LOCKDOWN_FILE ), array(), WP_SECURITY_LOCKDOWN_VERSION );
	}

	/**
	 * One-off pointer after activation.
	 *
	 * @return void
	 */
	public function activation_notice() {
		if ( ! current_user_can( self::CAPABILITY ) || ! get_transient( Activator::NOTICE_TRANSIENT ) ) {
			return;
		}
		$screen = get_current_screen();
		if ( $screen && 'settings_page_' . self::SLUG === $screen->id ) {
			delete_transient( Activator::NOTICE_TRANSIENT );
			return;
		}
		printf(
			'<div class="notice notice-info is-dismissible"><p><strong>%1$s</strong> %2$s <a href="%3$s">%4$s</a></p></div>',
			esc_html__( 'WP Security Lockdown is active.', 'wp-security-lockdown' ),
			esc_html__( 'The policy was applied, but HTTP verification has not run yet, so nothing is reported as verified.', 'wp-security-lockdown' ),
			esc_url( self::url( 'overview' ) ),
			esc_html__( 'Open the dashboard and run verification', 'wp-security-lockdown' )
		);
	}

	/* ===================================================================== rendering */

	/**
	 * Renders the dashboard (capability checked; the tab name is whitelisted).
	 *
	 * @return void
	 */
	public function render() {
		if ( ! current_user_can( self::CAPABILITY ) ) {
			wp_die( esc_html__( 'Sorry, you are not allowed to access this page.', 'wp-security-lockdown' ), '', array( 'response' => 403 ) );
		}

		$tab = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : 'overview'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- navigation only; whitelisted below.
		if ( ! in_array( $tab, self::TABS, true ) ) {
			$tab = 'overview';
		}

		$view = array(
			'plugin' => $this->plugin,
			'tab'    => $tab,
			'notice' => $this->take_notice(),
		);
		switch ( $tab ) {
			case 'overview':
				$view['reports'] = $this->plugin->policy()->reports();
				$view['summary'] = \WP_Security_Lockdown\Policy_Manager::summarize( $view['reports'] );
				$view['checks']  = $this->plugin->health()->all();
				break;
			case 'controls':
				$view['reports'] = $this->plugin->policy()->reports();
				break;
			case 'checks':
				$view['reports'] = $this->plugin->policy()->reports();
				$view['checks']  = $this->plugin->health()->all();
				break;
			case 'audit':
				$view['entries'] = $this->plugin->logger()->entries( 150 );
				break;
			case 'rollback':
				$view['ledger'] = $this->plugin->rollback()->describe();
				$view['detail'] = $this->take_rollback_detail();
				break;
		}//end switch

		$this->include_view( 'page', $view );
	}

	/**
	 * Includes a template with `$view` available. Templates live in admin/views and are never selected by user input.
	 *
	 * @param string $name Template name (no extension).
	 * @param array  $view Template data.
	 * @return void
	 */
	public function include_view( $name, array $view ) {
		$view['admin'] = $this;
		$file          = WP_SECURITY_LOCKDOWN_DIR . 'admin/views/' . $name . '.php';
		if ( preg_match( '/^[a-z-]+$/', $name ) && is_file( $file ) ) {
			include $file;
		}
	}

	/* ===================================================================== settings (Settings API) */

	/**
	 * Registers sections and fields on the Settings API.
	 *
	 * @return void
	 */
	public function register_settings_ui() {
		$page = self::SLUG;

		add_settings_section( 'wpsl_comments', __( 'Comments and trackbacks', 'wp-security-lockdown' ), '__return_false', $page );
		$this->checkbox( 'comments.enabled', 'wpsl_comments', __( 'Disable comments, trackbacks and pingbacks', 'wp-security-lockdown' ), __( 'Existing comments are kept. Editor Notes are not affected.', 'wp-security-lockdown' ) );

		add_settings_section( 'wpsl_xmlrpc', __( 'XML-RPC', 'wp-security-lockdown' ), '__return_false', $page );
		$this->select(
			'xmlrpc.mode',
			'wpsl_xmlrpc',
			__( 'XML-RPC', 'wp-security-lockdown' ),
			array(
				'block' => __( 'Block (recommended): every request to xmlrpc.php gets HTTP 403', 'wp-security-lockdown' ),
				'allow' => __( 'Allow (I explicitly need XML-RPC): pingback methods are still removed', 'wp-security-lockdown' ),
			),
			__( 'Jetpack, older mobile apps and desktop blog editors need XML-RPC.', 'wp-security-lockdown' )
		);

		add_settings_section( 'wpsl_rest', __( 'REST API', 'wp-security-lockdown' ), array( $this, 'rest_section_intro' ), $page );
		$this->select(
			'rest.mode',
			'wpsl_rest',
			__( 'Access policy', 'wp-security-lockdown' ),
			array(
				'off'            => __( 'Off: do not restrict the REST API', 'wp-security-lockdown' ),
				'restricted'     => __( 'Restricted (recommended): anonymous requests get 401', 'wp-security-lockdown' ),
				'dashboard_only' => __( 'Dashboard only (POTENTIALLY BREAKING): only the wp-admin UI may use the REST API', 'wp-security-lockdown' ),
			),
			''
		);
		$this->textarea( 'rest.public_namespaces', 'wpsl_rest', __( 'Public namespaces', 'wp-security-lockdown' ), __( 'One per line, e.g. contact-form-7/v1. Anonymous visitors may use these. Core admin namespaces are refused here on purpose. Ignored in Dashboard-only mode.', 'wp-security-lockdown' ) );
		$this->textarea( 'rest.dashboard_namespaces', 'wpsl_rest', __( 'Extra dashboard namespaces', 'wp-security-lockdown' ), __( 'Dashboard-only mode: additional namespaces that logged-in dashboard sessions (cookie + nonce) may use, for plugins whose admin screens call their own REST routes.', 'wp-security-lockdown' ) );

		add_settings_section( 'wpsl_login', __( 'Login protection', 'wp-security-lockdown' ), array( $this, 'login_section_intro' ), $page );
		$this->checkbox( 'login.limiter', 'wpsl_login', __( 'Rate limit failed logins', 'wp-security-lockdown' ), __( 'Blocks a client address, never an account.', 'wp-security-lockdown' ) );
		$this->number( 'login.max_attempts', 'wpsl_login', __( 'Failed attempts before a block', 'wp-security-lockdown' ), 3, 20, '' );
		$this->number( 'login.window', 'wpsl_login', __( 'Counting window (seconds)', 'wp-security-lockdown' ), 60, DAY_IN_SECONDS, '' );
		$this->number( 'login.lockout', 'wpsl_login', __( 'Block duration (seconds)', 'wp-security-lockdown' ), 60, DAY_IN_SECONDS, __( 'Every block expires by itself; nothing is permanent.', 'wp-security-lockdown' ) );
		$this->textarea( 'login.allowlist', 'wpsl_login', __( 'Never block these addresses', 'wp-security-lockdown' ), __( 'IP addresses or CIDR ranges, one per line (for example your office). Safe recovery path.', 'wp-security-lockdown' ) );
		$this->textarea( 'login.trusted_proxies', 'wpsl_login', __( 'Trusted reverse proxies', 'wp-security-lockdown' ), __( 'IP addresses / CIDR ranges of proxies or CDNs YOU operate, one per line. Forwarded-for headers are ignored unless the connection comes from one of these.', 'wp-security-lockdown' ) );
		$this->select(
			'login.proxy_header',
			'wpsl_login',
			__( 'Client IP header', 'wp-security-lockdown' ),
			array(
				''                 => __( 'None: use the connecting address (REMOTE_ADDR)', 'wp-security-lockdown' ),
				'X-Forwarded-For'  => 'X-Forwarded-For',
				'X-Real-IP'        => 'X-Real-IP',
				'CF-Connecting-IP' => 'CF-Connecting-IP (Cloudflare)',
				'True-Client-IP'   => 'True-Client-IP',
				'Fastly-Client-IP' => 'Fastly-Client-IP',
			),
			__( 'Only used when the request comes from a trusted proxy above.', 'wp-security-lockdown' )
		);
		$this->checkbox( 'login.generic_errors', 'wpsl_login', __( 'Generic login errors', 'wp-security-lockdown' ), __( 'Do not reveal whether a user name exists.', 'wp-security-lockdown' ) );
		$this->number( 'login.min_password_length', 'wpsl_login', __( 'Minimum password length', 'wp-security-lockdown' ), 0, 64, __( '0 turns the policy off; otherwise 8 to 64. Length matters more than composition rules.', 'wp-security-lockdown' ) );

		add_settings_section( 'wpsl_disclosure', __( 'Information disclosure', 'wp-security-lockdown' ), '__return_false', $page );
		$this->checkbox( 'disclosure.author_enumeration', 'wpsl_disclosure', __( 'Block author enumeration', 'wp-security-lockdown' ), __( '?author=N, users sitemap, anonymous REST users.', 'wp-security-lockdown' ) );
		$this->checkbox( 'disclosure.version', 'wpsl_disclosure', __( 'Hide WordPress version', 'wp-security-lockdown' ), __( 'Hygiene only; it does not make an unpatched site safe.', 'wp-security-lockdown' ) );
		$this->checkbox( 'disclosure.discovery', 'wpsl_disclosure', __( 'Remove discovery links and headers', 'wp-security-lockdown' ), __( 'REST, oEmbed and shortlink advertisements. Not access control.', 'wp-security-lockdown' ) );
		$this->checkbox( 'disclosure.error_display', 'wpsl_disclosure', __( 'Never display PHP errors to visitors', 'wp-security-lockdown' ), __( 'Skipped on local / development environments.', 'wp-security-lockdown' ) );

		add_settings_section( 'wpsl_files', __( 'Files', 'wp-security-lockdown' ), '__return_false', $page );
		$this->checkbox( 'files.file_editor', 'wpsl_files', __( 'Disable the dashboard theme / plugin editor', 'wp-security-lockdown' ), __( 'wp-config.php is never edited by this plugin.', 'wp-security-lockdown' ) );

		add_settings_section( 'wpsl_lifecycle', __( 'Lifecycle', 'wp-security-lockdown' ), '__return_false', $page );
		$this->checkbox( 'lifecycle.rollback_on_deactivation', 'wpsl_lifecycle', __( 'Restore original settings when the plugin is deactivated', 'wp-security-lockdown' ), __( 'Off by default: deactivation stops the runtime protections but leaves the three discussion defaults as they are. Values changed by someone else are never overwritten.', 'wp-security-lockdown' ) );
	}

	/**
	 * Explains the REST policy above its fields.
	 *
	 * @return void
	 */
	public function rest_section_intro() {
		echo '<p>' . esc_html__( 'Logged-in requests are never given extra access here: every endpoint\'s own permission check still applies. The block editor, site editor and Site Health keep working in Restricted mode because they call the API with a logged-in session.', 'wp-security-lockdown' ) . '</p>';
	}

	/**
	 * Explains the login settings and the recovery constant above their fields.
	 *
	 * @return void
	 */
	public function login_section_intro() {
		echo '<p>' . esc_html__( 'Recovery if you lock yourself out: wait for the block to expire, use another network, or add this to wp-config.php: define( \'WP_SECURITY_LOCKDOWN_DISABLE_LOGIN_LIMITER\', true );', 'wp-security-lockdown' ) . '</p>';
	}

	/**
	 * Registers a checkbox field.
	 *
	 * @param string $path    Dotted settings path.
	 * @param string $section Section id.
	 * @param string $label   Field label.
	 * @param string $help    Help text.
	 * @return void
	 */
	private function checkbox( $path, $section, $label, $help ) {
		add_settings_field(
			'wpsl_' . $path,
			$label,
			array( $this, 'render_checkbox' ),
			self::SLUG,
			$section,
			array(
				'path'      => $path,
				'help'      => $help,
				'label_for' => 'wpsl-' . str_replace( '.', '-', $path ),
			)
		);
	}

	/**
	 * Registers a select field.
	 *
	 * @param string $path    Dotted settings path.
	 * @param string $section Section id.
	 * @param string $label   Field label.
	 * @param array  $options value => label.
	 * @param string $help    Help text.
	 * @return void
	 */
	private function select( $path, $section, $label, array $options, $help ) {
		add_settings_field(
			'wpsl_' . $path,
			$label,
			array( $this, 'render_select' ),
			self::SLUG,
			$section,
			array(
				'path'      => $path,
				'options'   => $options,
				'help'      => $help,
				'label_for' => 'wpsl-' . str_replace( '.', '-', $path ),
			)
		);
	}

	/**
	 * Registers a number field.
	 *
	 * @param string $path    Dotted settings path.
	 * @param string $section Section id.
	 * @param string $label   Field label.
	 * @param int    $min     Minimum.
	 * @param int    $max     Maximum.
	 * @param string $help    Help text.
	 * @return void
	 */
	private function number( $path, $section, $label, $min, $max, $help ) {
		add_settings_field(
			'wpsl_' . $path,
			$label,
			array( $this, 'render_number' ),
			self::SLUG,
			$section,
			array(
				'path'      => $path,
				'min'       => $min,
				'max'       => $max,
				'help'      => $help,
				'label_for' => 'wpsl-' . str_replace( '.', '-', $path ),
			)
		);
	}

	/**
	 * Registers a list field (one entry per line).
	 *
	 * @param string $path    Dotted settings path.
	 * @param string $section Section id.
	 * @param string $label   Field label.
	 * @param string $help    Help text.
	 * @return void
	 */
	private function textarea( $path, $section, $label, $help ) {
		add_settings_field(
			'wpsl_' . $path,
			$label,
			array( $this, 'render_textarea' ),
			self::SLUG,
			$section,
			array(
				'path'      => $path,
				'help'      => $help,
				'label_for' => 'wpsl-' . str_replace( '.', '-', $path ),
			)
		);
	}

	/**
	 * Input name for a dotted path: wp_security_lockdown_settings[section][key].
	 *
	 * @param string $path Dotted path.
	 * @return string
	 */
	private function field_name( $path ) {
		list( $section, $key ) = explode( '.', $path, 2 );
		return Settings_Repository::OPTION . '[' . $section . '][' . $key . ']';
	}

	/**
	 * Prints a checkbox field, with a hidden 0 so an unchecked box is still submitted.
	 *
	 * @param array $args Field args.
	 * @return void
	 */
	public function render_checkbox( $args ) {
		$name  = $this->field_name( $args['path'] );
		$value = (bool) $this->plugin->settings()->get( $args['path'] );
		printf(
			'<input type="hidden" name="%1$s" value="0" /><label><input type="checkbox" id="%2$s" name="%1$s" value="1" %3$s /> %4$s</label>',
			esc_attr( $name ),
			esc_attr( $args['label_for'] ),
			checked( $value, true, false ),
			esc_html( $args['help'] )
		);
	}

	/**
	 * Prints a select field.
	 *
	 * @param array $args Field args.
	 * @return void
	 */
	public function render_select( $args ) {
		$current = (string) $this->plugin->settings()->get( $args['path'] );
		printf( '<select id="%1$s" name="%2$s">', esc_attr( $args['label_for'] ), esc_attr( $this->field_name( $args['path'] ) ) );
		foreach ( $args['options'] as $value => $label ) {
			printf( '<option value="%1$s" %2$s>%3$s</option>', esc_attr( $value ), selected( $current, (string) $value, false ), esc_html( $label ) );
		}
		echo '</select>';
		if ( '' !== $args['help'] ) {
			echo '<p class="description">' . esc_html( $args['help'] ) . '</p>';
		}
	}

	/**
	 * Prints a number field.
	 *
	 * @param array $args Field args.
	 * @return void
	 */
	public function render_number( $args ) {
		printf(
			'<input type="number" class="small-text" id="%1$s" name="%2$s" value="%3$d" min="%4$d" max="%5$d" />',
			esc_attr( $args['label_for'] ),
			esc_attr( $this->field_name( $args['path'] ) ),
			(int) $this->plugin->settings()->get( $args['path'] ),
			(int) $args['min'],
			(int) $args['max']
		);
		if ( '' !== $args['help'] ) {
			echo '<p class="description">' . esc_html( $args['help'] ) . '</p>';
		}
	}

	/**
	 * Prints a list field.
	 *
	 * @param array $args Field args.
	 * @return void
	 */
	public function render_textarea( $args ) {
		$list = (array) $this->plugin->settings()->get( $args['path'], array() );
		printf(
			'<textarea class="large-text code" rows="4" id="%1$s" name="%2$s" spellcheck="false">%3$s</textarea>',
			esc_attr( $args['label_for'] ),
			esc_attr( $this->field_name( $args['path'] ) ),
			esc_textarea( implode( "\n", $list ) )
		);
		if ( '' !== $args['help'] ) {
			echo '<p class="description">' . esc_html( $args['help'] ) . '</p>';
		}
	}

	/* ===================================================================== state-changing handlers */

	/**
	 * POST + capability + nonce, in that order. Dies (403/405) otherwise.
	 *
	 * @param string $action Nonce action (same as the admin-post action).
	 * @return void
	 */
	protected function authorize( $action ) {
		$method = isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '';
		if ( 'POST' !== $method ) {
			wp_die( esc_html__( 'This action must be submitted as a form.', 'wp-security-lockdown' ), '', array( 'response' => 405 ) );
		}
		if ( ! current_user_can( self::CAPABILITY ) ) {
			wp_die( esc_html__( 'Sorry, you are not allowed to do that.', 'wp-security-lockdown' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( $action );
	}

	/**
	 * Runs verification (with real HTTP requests) and the deep diagnostics.
	 *
	 * @return void
	 */
	public function handle_verify() {
		$this->authorize( 'wp_security_lockdown_verify' );

		// The probes are bounded to 25 seconds in total, but PHP's default limit is often 30 for the whole request.
		if ( function_exists( 'set_time_limit' ) ) {
			@set_time_limit( 60 ); // phpcs:ignore Squiz.PHP.DiscouragedFunctions.Discouraged, WordPress.PHP.NoSilencedErrors.Discouraged -- admin-initiated, may be disabled by the host.
		}

		$probe = new Http_Probe( 25.0 );
		$probe->attach_current_session();
		$this->plugin->policy()->verify( true, $probe );
		$this->plugin->health()->run( true, $probe );

		$this->finish( 'verified', 'overview' );
	}

	/**
	 * Re-applies the policy to the persistent options (explicitly overriding drift).
	 *
	 * @return void
	 */
	public function handle_apply() {
		$this->authorize( 'wp_security_lockdown_apply' );

		$this->plugin->policy()->apply_all();
		$this->plugin->policy()->verify( false );
		$this->finish( 'applied', 'overview' );
	}

	/**
	 * Rolls back the plugin's own persistent changes.
	 *
	 * @return void
	 */
	public function handle_rollback() {
		$this->authorize( 'wp_security_lockdown_rollback' );

		$force  = isset( $_POST['force'] ) && '1' === sanitize_text_field( wp_unslash( $_POST['force'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- verified in authorize().
		$result = $this->plugin->policy()->rollback( $force );
		set_transient( 'wp_security_lockdown_rollback_' . get_current_user_id(), $result, 5 * MINUTE_IN_SECONDS );
		$this->plugin->policy()->verify( false );
		$this->finish( $result['conflicts'] ? 'rolled_back_conflicts' : 'rolled_back', 'rollback' );
	}

	/**
	 * Clears all login lockouts (a recovery tool for administrators who are still logged in).
	 *
	 * @return void
	 */
	public function handle_clear_lockouts() {
		$this->authorize( 'wp_security_lockdown_clear_lockouts' );

		Rate_Limiter::clear_all();
		$this->plugin->logger()->info( 'lockouts_cleared', 'All login lockouts were cleared by an administrator.' );
		$this->finish( 'lockouts_cleared', 'overview' );
	}

	/**
	 * Remembers a result code for the next page view and redirects.
	 *
	 * @param string $code Key of the fixed message table.
	 * @param string $tab  Tab to land on.
	 * @return void
	 */
	protected function finish( $code, $tab ) {
		set_transient( 'wp_security_lockdown_notice_' . get_current_user_id(), $code, MINUTE_IN_SECONDS );
		wp_safe_redirect( self::url( $tab ) );
		$this->terminate();
	}

	/**
	 * Ends the request. Separate so tests can observe handlers.
	 *
	 * @return void
	 */
	protected function terminate() {
		exit;
	}

	/**
	 * Reads and deletes the pending notice code and returns its fixed message.
	 *
	 * @return array|null array( type, message ) or null.
	 */
	private function take_notice() {
		$key  = 'wp_security_lockdown_notice_' . get_current_user_id();
		$code = get_transient( $key );
		if ( false === $code ) {
			return null;
		}
		delete_transient( $key );

		$messages = array(
			'verified'              => array( 'success', __( 'Verification and diagnostics finished. Statuses below reflect what was actually observed.', 'wp-security-lockdown' ) ),
			'applied'               => array( 'success', __( 'The policy was applied to the persistent options (nothing is written when a value is already correct).', 'wp-security-lockdown' ) ),
			'rolled_back'           => array( 'success', __( 'Rollback finished: the plugin-owned settings were restored.', 'wp-security-lockdown' ) ),
			'rolled_back_conflicts' => array( 'warning', __( 'Rollback finished with conflicts: some settings were changed after the plugin set them and were NOT restored (see below).', 'wp-security-lockdown' ) ),
			'lockouts_cleared'      => array( 'success', __( 'All login lockouts were cleared.', 'wp-security-lockdown' ) ),
		);
		return is_string( $code ) && isset( $messages[ $code ] ) ? $messages[ $code ] : null;
	}

	/**
	 * Reads and deletes the detailed rollback result.
	 *
	 * @return array|null
	 */
	private function take_rollback_detail() {
		$key    = 'wp_security_lockdown_rollback_' . get_current_user_id();
		$detail = get_transient( $key );
		if ( false === $detail ) {
			return null;
		}
		delete_transient( $key );
		return is_array( $detail ) ? $detail : null;
	}
}
