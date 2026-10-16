<?php
/**
 * Comments, trackbacks and pingbacks.
 *
 * @package WP_Security_Lockdown
 */

namespace WP_Security_Lockdown\Modules;

use WP_Security_Lockdown\Abstract_Module;
use WP_Security_Lockdown\Http_Probe;

defined( 'ABSPATH' ) || exit;

/**
 * Control `comments`: no new public comment, trackback or pingback can be created, anywhere.
 *
 * Entry points covered, and how:
 *  - Front-end form (wp-comments-post.php) ........ `comments_open` => false (core answers "comments are closed", HTTP 403)
 *  - Existing posts' comment forms ................ same filter; stored post settings are NOT modified
 *  - Trackbacks (wp-trackback.php), pingbacks ..... `pings_open` => false
 *  - REST POST /wp/v2/comments .................... core honours `comments_open`; `rest_pre_insert_comment` rejects as a second layer
 *  - Every other wp_new_comment() caller .......... `pre_comment_approved` returns a WP_Error for public comment types
 *    (XML-RPC wp.newComment / pingback.ping, admin "quick reply", plugins)
 *  - Defaults for new content ..................... persistent options, recorded in the ledger so they can be rolled back
 *
 * Deliberately NOT affected: existing comments (kept and still displayed), comment moderation,
 * editor Notes (comment type "note", WordPress 6.9+: editorial feedback, not public comments), and
 * programmatic wp_insert_comment() calls (importers, system log comments).
 */
class Comments_Hardening extends Abstract_Module {

	const DEFAULT_BLOCKED_TYPES = array( '', 'comment', 'pingback', 'trackback', 'review' );

	/** Plugins whose features are built on public comments. */
	const DEPENDENT_PLUGINS = array(
		'woocommerce/woocommerce.php'      => 'WooCommerce product reviews are comments; they are closed as well.',
		'jetpack/jetpack.php'              => 'Jetpack Comments / Subscriptions for comments stop working while comments are closed.',
		'disqus-comment-system/disqus.php' => 'Disqus replaces the comment form; the embedded thread will show as closed.',
		'wpdiscuz/class.WpdiscuzCore.php'  => 'wpDiscuz renders its own comment UI; new comments will be rejected.',
	);

	/**
	 * Returns the module slug.
	 *
	 * @return string
	 */
	public function slug() {
		return 'comments_hardening';
	}

	/**
	 * Returns the control definitions.
	 *
	 * @return array
	 */
	public function controls() {
		return array(
			'comments' => array(
				'title'       => __( 'Comments, trackbacks and pingbacks', 'wp-security-lockdown' ),
				'description' => __( 'Closes comments and pings on all content and rejects new public comments from every entry point. Existing comments are kept.', 'wp-security-lockdown' ),
			),
		);
	}

	/**
	 * Registers the comment and ping filters when the control is on.
	 *
	 * @return void
	 */
	public function register() {
		if ( ! $this->plugin->settings()->control_enabled( 'comments' ) ) {
			return;
		}
		add_filter( 'comments_open', '__return_false', 999 );
		add_filter( 'pings_open', '__return_false', 999 );
		add_filter( 'pre_comment_approved', array( $this, 'reject_public_comment' ), 999, 2 );
		add_filter( 'rest_pre_insert_comment', array( $this, 'reject_rest_comment' ), 999, 2 );
		add_filter( 'wp_headers', array( $this, 'drop_pingback_header' ), 999 );
	}

	/**
	 * Persistent defaults for newly created content.
	 *
	 * @return array
	 */
	public function managed_options() {
		return array(
			'comments' => array(
				'default_comment_status' => 'closed',
				'default_ping_status'    => 'closed',
				'default_pingback_flag'  => '0',
			),
		);
	}

	/**
	 * Comment types that count as "public" and are therefore refused.
	 *
	 * @return string[]
	 */
	public function blocked_types() {
		/**
		 * Filters which comment types are rejected while comments are disabled.
		 * The editor "note" type is intentionally absent and should stay absent.
		 *
		 * @param string[] $types Comment types ('' means the default type, "comment").
		 */
		$types = apply_filters( 'wp_security_lockdown_blocked_comment_types', self::DEFAULT_BLOCKED_TYPES );
		return is_array( $types ) ? array_map( 'strval', $types ) : self::DEFAULT_BLOCKED_TYPES;
	}

	/**
	 * `pre_comment_approved`: refuses to create a public comment. Runs inside wp_new_comment().
	 *
	 * @param mixed $approved     Approval status or WP_Error from earlier filters.
	 * @param array $comment_data The comment being created.
	 * @return mixed
	 */
	public function reject_public_comment( $approved, $comment_data = array() ) {
		if ( is_wp_error( $approved ) ) {
			return $approved;
		}
		$type = is_array( $comment_data ) && isset( $comment_data['comment_type'] ) ? (string) $comment_data['comment_type'] : '';

		if ( in_array( $type, $this->blocked_types(), true ) ) {
			return new \WP_Error( 'wp_security_lockdown_comments_closed', __( 'Comments are disabled on this site.', 'wp-security-lockdown' ), array( 'status' => 403 ) );
		}
		return $approved;
	}

	/**
	 * `rest_pre_insert_comment`: rejects creating a public comment over REST (this filter only runs on create).
	 *
	 * @param array|\WP_Error  $prepared_comment Prepared comment data.
	 * @param \WP_REST_Request $request         Request.
	 * @return array|\WP_Error
	 */
	public function reject_rest_comment( $prepared_comment, $request = null ) {
		unset( $request );
		if ( is_wp_error( $prepared_comment ) ) {
			return $prepared_comment;
		}
		$type = is_array( $prepared_comment ) && isset( $prepared_comment['comment_type'] ) ? (string) $prepared_comment['comment_type'] : '';
		if ( in_array( $type, $this->blocked_types(), true ) ) {
			return new \WP_Error( 'rest_comment_closed', __( 'Sorry, comments are closed for this item.', 'wp-security-lockdown' ), array( 'status' => 403 ) );
		}
		return $prepared_comment;
	}

	/**
	 * `wp_headers`: never advertise a pingback endpoint.
	 *
	 * @param array $headers Response headers.
	 * @return array
	 */
	public function drop_pingback_header( $headers ) {
		if ( is_array( $headers ) ) {
			unset( $headers['X-Pingback'] );
		}
		return $headers;
	}

	/**
	 * Control id => report (the shape Policy_Manager expects).
	 *
	 * @return array
	 */
	public function report() {
		return array( 'comments' => $this->build_report() );
	}

	/**
	 * Builds the report of this module's single control.
	 *
	 * @return array
	 */
	private function build_report() {
		$report = $this->make_report(
			'comments',
			array(
				'desired'     => __( 'No new public comment, trackback or pingback can be created on any content. Editor Notes are not affected.', 'wp-security-lockdown' ),
				'enforcement' => array(
					__( 'Runtime filters: comments_open, pings_open, pre_comment_approved, rest_pre_insert_comment (stop when the plugin is deactivated).', 'wp-security-lockdown' ),
					__( 'Persistent options: default_comment_status, default_ping_status, default_pingback_flag (stay in effect after deactivation until rolled back).', 'wp-security-lockdown' ),
				),
				'persists'    => __( 'The three discussion defaults for new content stay "closed" after deactivation until you roll them back.', 'wp-security-lockdown' ),
			)
		);

		foreach ( self::DEPENDENT_PLUGINS as $file => $note ) {
			if ( $this->plugin_active( $file ) ) {
				$report['warnings'][] = $note;
			}
		}

		if ( ! $report['enabled'] ) {
			$report['state'] = self::STATE_DISABLED;
			return $report;
		}

		$missing = array();
		foreach ( array(
			'comments_open'           => '__return_false',
			'pings_open'              => '__return_false',
			'pre_comment_approved'    => array( $this, 'reject_public_comment' ),
			'rest_pre_insert_comment' => array( $this, 'reject_rest_comment' ),
		) as $hook => $callback ) {
			$present = $this->hooked( $hook, $callback );
			if ( ! $present ) {
				$missing[] = $hook;
			}
			$report['details'][] = array(
				'label'  => $hook,
				'status' => $present ? 'ok' : 'fail',
				'text'   => $present ? __( 'Filter is attached.', 'wp-security-lockdown' ) : __( 'Filter is NOT attached.', 'wp-security-lockdown' ),
			);
		}

		$drifted = array();
		foreach ( $this->managed_options()['comments'] as $option => $desired ) {
			$current = get_option( $option, null );
			$same    = $this->plugin->rollback()->equal( $current, $desired );
			if ( ! $same ) {
				$drifted[] = $option;
			}
			$report['details'][] = array(
				'label'  => $option,
				'status' => $same ? 'ok' : 'warn',
				/* translators: 1: current value, 2: desired value. */
				'text'   => $same ? sprintf( __( 'Set to "%s".', 'wp-security-lockdown' ), $desired ) : sprintf( __( 'Currently "%1$s", policy wants "%2$s". Runtime filters still keep comments closed; use "Re-apply policy" to restore the default.', 'wp-security-lockdown' ), is_scalar( $current ) ? (string) $current : '?', $desired ),
			);
		}

		if ( $missing ) {
			$report['state']          = self::STATE_FAILED;
			$report['failure_reason'] = sprintf(
				/* translators: %s: comma separated filter names. */
				__( 'Not enforced in this request: %s.', 'wp-security-lockdown' ),
				implode( ', ', $missing )
			);
		} elseif ( $drifted ) {
			$report['state']          = self::STATE_PARTIAL;
			$report['failure_reason'] = sprintf(
				/* translators: %s: comma separated option names. */
				__( 'Runtime protection is active, but these defaults for new content were changed after the policy set them: %s.', 'wp-security-lockdown' ),
				implode( ', ', $drifted )
			);
		} else {
			$report['state'] = self::STATE_ENFORCED;
		}
		return $report;
	}

	// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- verification deliberately invokes core hooks to prove this plugin's callbacks act on them.
	/**
	 * Verifies the control inside PHP and, when a probe is given, over HTTP.
	 *
	 * @param Http_Probe|null $probe Probe or null.
	 * @return array
	 */
	public function verify( ?Http_Probe $probe = null ) {
		if ( ! $this->plugin->settings()->control_enabled( 'comments' ) ) {
			return array();
		}

		// Feed the filters an "open" value and require them to turn it into "closed". (Do not call comments_open()
		// on a synthetic post: get_post() returns null for it, so the answer would be false with or without this control.).
		$local   = array();
		$local[] = array( false === apply_filters( 'comments_open', true, 0 ), 'the comments_open filter turns "open" into "closed"' );
		$local[] = array( false === apply_filters( 'pings_open', true, 0 ), 'the pings_open filter turns "open" into "closed"' );

		$comment = apply_filters( 'pre_comment_approved', 1, array( 'comment_type' => 'comment' ) );
		$local[] = array( is_wp_error( $comment ), 'wp_new_comment() would reject a public comment' );
		$note    = apply_filters( 'pre_comment_approved', 1, array( 'comment_type' => 'note' ) );
		$local[] = array( ! is_wp_error( $note ), 'editor Notes are still allowed' );

		$rest    = apply_filters( 'rest_pre_insert_comment', array( 'comment_type' => 'comment' ), new \WP_REST_Request( 'POST', '/wp/v2/comments' ) );
		$local[] = array( is_wp_error( $rest ), 'REST comment creation would be rejected' );

		// The persistent defaults are deliberately NOT part of this verdict. Whether they match the policy is the control's
		// "state" (partial when they drifted); the verification proves the protective effect itself, which holds either way.

		$http   = array();
		$reason = __( 'No HTTP probe was run.', 'wp-security-lockdown' );
		if ( $probe ) {
			$reason = $this->probe_http( $probe, $http );
		}
		return array( 'comments' => $this->conclude( $local, $http, false, $reason ) );
	}
	// phpcs:enable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound

	/**
	 * Real requests against the form handler (never creates a comment: the payload is empty).
	 *
	 * @param Http_Probe $probe Probe.
	 * @param array      $http  Collector for check results.
	 * @return string Why no HTTP check ran, or ''.
	 */
	private function probe_http( Http_Probe $probe, array &$http ) {
		$preflight = $probe->preflight();
		if ( ! $preflight['ok'] ) {
			/* translators: %s: error code. */
			return sprintf( __( 'HTTP probe unavailable (%s).', 'wp-security-lockdown' ), $preflight['error'] );
		}

		$ids = get_posts(
			array(
				'post_type'        => 'post',
				'post_status'      => 'publish',
				'posts_per_page'   => 1,
				'fields'           => 'ids',
				'no_found_rows'    => true,
				'suppress_filters' => true,
			)
		);
		if ( ! $ids ) {
			return __( 'No published post exists to test against.', 'wp-security-lockdown' );
		}
		$post_id = (int) $ids[0];

		// An EMPTY comment can never be stored; if comments were open the form would answer with a
		// validation message (HTTP 200), if closed it answers 403.
		$response = $probe->request(
			'POST',
			site_url( 'wp-comments-post.php' ),
			array(
				'body' => array(
					'comment_post_ID' => $post_id,
					'comment'         => '',
					'author'          => '',
					'email'           => '',
				),
			)
		);
		if ( $response['ok'] ) {
			$http[] = array(
				403 === $response['code'],
				sprintf( 'POST wp-comments-post.php answered HTTP %d (403 expected)', $response['code'] ),
			);
		}

		if ( $probe->has_session() ) {
			// Empty content is never stored either, so this probes the permission path only.
			$rest = $probe->request(
				'POST',
				add_query_arg( 'rest_route', '/wp/v2/comments', home_url( '/' ) ),
				array(
					'authenticated' => true,
					'headers'       => array( 'Content-Type' => 'application/json' ),
					'body'          => wp_json_encode(
						array(
							'post'    => $post_id,
							'content' => '',
						)
					),
				)
			);
			if ( $rest['ok'] ) {
				$http[] = array(
					403 === $rest['code'],
					sprintf( 'Authenticated REST POST /wp/v2/comments answered HTTP %d (403 expected)', $rest['code'] ),
				);
			}
		}//end if
		return $http ? '' : __( 'The HTTP requests could not be completed.', 'wp-security-lockdown' );
	}

	/**
	 * Whether a plugin is active.
	 *
	 * @param string $plugin_file Plugin basename.
	 * @return bool
	 */
	private function plugin_active( $plugin_file ) {
		return in_array( $plugin_file, (array) get_option( 'active_plugins', array() ), true );
	}
}
