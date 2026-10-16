<?php
/**
 * Overview tab.
 *
 * @package WP_Security_Lockdown
 * @var array $view Template data.
 */

defined( 'ABSPATH' ) || exit;

use WP_Security_Lockdown\Admin\Presenter;
use WP_Security_Lockdown\Health_Check;
use WP_Security_Lockdown\Policy_Manager;

$wpsl_reports = $view['reports'];
$wpsl_counts  = $view['summary']['counts'];
$wpsl_overall = $view['summary']['overall'];
$wpsl_checks  = Health_Check::summarize( $view['checks']['rows'] );
$wpsl_count   = static function ( array $statuses ) use ( $wpsl_counts ) {
	$total = 0;
	foreach ( $statuses as $status ) {
		$total += isset( $wpsl_counts[ $status ] ) ? (int) $wpsl_counts[ $status ] : 0;
	}
	return $total;
};

$wpsl_findings = (int) $wpsl_checks['fail'] + (int) $wpsl_checks['warn'];

/*
 * The verdict must not be greener than the facts: verified controls do not make a site secure while
 * server-level or account-level findings (which no plugin can fix) are still open.
 */
if ( 'ok' === $wpsl_overall && $wpsl_findings > 0 ) {
	$wpsl_head = array(
		'warn',
		sprintf(
			/* translators: %d: number of open findings. */
			_n( 'Every enabled control is enforced and verified, but %d finding on this site still needs action.', 'Every enabled control is enforced and verified, but %d findings on this site still need action.', $wpsl_findings, 'wp-security-lockdown' ),
			$wpsl_findings
		),
		__( 'Those findings are in areas a plugin cannot change: the web server, the filesystem, the database account and user accounts. Until they are handled the site is not fully hardened. See the Checks tab.', 'wp-security-lockdown' ),
	);
} else {
	$wpsl_headline = array(
		'ok'        => array( 'ok', __( 'Every enabled control is enforced and verified, and there are no open findings.', 'wp-security-lockdown' ), __( '"Verified" means the tested behaviour was observed. It is not a guarantee against every attack.', 'wp-security-lockdown' ) ),
		'attention' => array( 'warn', __( 'Some controls are not yet proven to work, or need your attention.', 'wp-security-lockdown' ), __( 'Controls that are configured but not verified are not counted as protection. Run verification, then review the items below.', 'wp-security-lockdown' ) ),
		'at_risk'   => array( 'bad', __( 'One or more controls are failing or not working.', 'wp-security-lockdown' ), __( 'The site is not protected the way the policy says. See the items below.', 'wp-security-lockdown' ) ),
	);
	$wpsl_head     = $wpsl_headline[ $wpsl_overall ];
}

// The most serious open findings (problems first), for the "open findings" list.
$wpsl_open = array_values(
	array_filter(
		$view['checks']['rows'],
		static function ( $row ) {
			return in_array( $row['status'], array( 'fail', 'warn' ), true );
		}
	)
);
usort(
	$wpsl_open,
	static function ( $a, $b ) {
		return ( 'fail' === $b['status'] ? 1 : 0 ) <=> ( 'fail' === $a['status'] ? 1 : 0 );
	}
);

$wpsl_attention = array();
foreach ( $wpsl_reports as $wpsl_report ) {
	if ( Policy_Manager::DISABLED === $wpsl_report['status'] ) {
		continue;
	}
	if ( ! in_array( $wpsl_report['status'], array( Policy_Manager::VERIFIED_HTTP, Policy_Manager::VERIFIED_LOCAL, Policy_Manager::MONITOR_OK ), true ) || '' !== $wpsl_report['manual_action'] ) {
		$wpsl_attention[] = $wpsl_report;
	}
}

$wpsl_last = 0;
foreach ( $view['plugin']->state()->verification() as $wpsl_v ) {
	$wpsl_last = max( $wpsl_last, is_array( $wpsl_v ) && isset( $wpsl_v['time'] ) && is_numeric( $wpsl_v['time'] ) ? (int) $wpsl_v['time'] : 0 );
}
?>
<div class="wpsl-banner wpsl-<?php echo esc_attr( $wpsl_head[0] ); ?>" role="status">
	<p class="wpsl-banner-title"><?php echo esc_html( $wpsl_head[1] ); ?></p>
	<p><?php echo esc_html( $wpsl_head[2] ); ?></p>
</div>

<ul class="wpsl-tiles">
	<li><strong><?php echo (int) $wpsl_count( array( Policy_Manager::VERIFIED_HTTP, Policy_Manager::VERIFIED_LOCAL, Policy_Manager::MONITOR_OK ) ); ?></strong> <?php esc_html_e( 'verified', 'wp-security-lockdown' ); ?></li>
	<li><strong><?php echo (int) $wpsl_count( array( Policy_Manager::UNVERIFIED ) ); ?></strong> <?php esc_html_e( 'enforced, not verified', 'wp-security-lockdown' ); ?></li>
	<li><strong><?php echo (int) $wpsl_count( array( Policy_Manager::PARTIAL, Policy_Manager::MONITOR_WARN ) ); ?></strong> <?php esc_html_e( 'partial / findings', 'wp-security-lockdown' ); ?></li>
	<li><strong><?php echo (int) $wpsl_count( array( Policy_Manager::FAILED, Policy_Manager::NOT_WORKING ) ); ?></strong> <?php esc_html_e( 'failed / not working', 'wp-security-lockdown' ); ?></li>
	<li><strong><?php echo (int) $wpsl_count( array( Policy_Manager::DISABLED ) ); ?></strong> <?php esc_html_e( 'disabled by policy', 'wp-security-lockdown' ); ?></li>
	<li><strong><?php echo (int) $wpsl_findings; ?></strong> <?php esc_html_e( 'open findings (manual / server-level)', 'wp-security-lockdown' ); ?></li>
</ul>

<div class="wpsl-actions">
	<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
		<input type="hidden" name="action" value="wp_security_lockdown_verify" />
		<?php wp_nonce_field( 'wp_security_lockdown_verify' ); ?>
		<?php submit_button( __( 'Run verification and diagnostics', 'wp-security-lockdown' ), 'primary', 'submit', false ); ?>
		<span class="description"><?php esc_html_e( 'Sends a bounded number of real requests to this site (at most 40, within a 25-second budget) and tests the controls end to end.', 'wp-security-lockdown' ); ?></span>
	</form>
	<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
		<input type="hidden" name="action" value="wp_security_lockdown_apply" />
		<?php wp_nonce_field( 'wp_security_lockdown_apply' ); ?>
		<?php submit_button( __( 'Re-apply policy', 'wp-security-lockdown' ), 'secondary', 'submit', false ); ?>
		<span class="description"><?php esc_html_e( 'Writes the persistent options again if someone changed them. Safe to repeat: nothing is written when a value is already right.', 'wp-security-lockdown' ); ?></span>
	</form>
	<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
		<input type="hidden" name="action" value="wp_security_lockdown_clear_lockouts" />
		<?php wp_nonce_field( 'wp_security_lockdown_clear_lockouts' ); ?>
		<?php submit_button( __( 'Clear login lockouts', 'wp-security-lockdown' ), 'secondary', 'submit', false ); ?>
	</form>
</div>

<p class="description">
	<?php
	printf(
		/* translators: 1: time of last control verification, 2: time of last deep diagnostics. */
		esc_html__( 'Last control verification: %1$s. Last deep diagnostics: %2$s.', 'wp-security-lockdown' ),
		esc_html( Presenter::when( $wpsl_last ) ),
		esc_html( Presenter::when( $view['checks']['deep_time'] ) )
	);
	?>
</p>

<h2><?php esc_html_e( 'Needs attention', 'wp-security-lockdown' ); ?></h2>
<?php if ( ! $wpsl_attention ) : ?>
	<p><?php esc_html_e( 'Nothing needs attention among the enabled controls.', 'wp-security-lockdown' ); ?></p>
<?php else : ?>
	<div class="wpsl-scroll">
	<table class="widefat striped wpsl-table">
		<caption class="screen-reader-text"><?php esc_html_e( 'Controls that need attention', 'wp-security-lockdown' ); ?></caption>
		<thead><tr>
			<th scope="col"><?php esc_html_e( 'Control', 'wp-security-lockdown' ); ?></th>
			<th scope="col"><?php esc_html_e( 'Status', 'wp-security-lockdown' ); ?></th>
			<th scope="col"><?php esc_html_e( 'Why', 'wp-security-lockdown' ); ?></th>
		</tr></thead>
		<tbody>
		<?php foreach ( $wpsl_attention as $wpsl_report ) : ?>
			<tr>
				<td><strong><?php echo esc_html( $wpsl_report['title'] ); ?></strong></td>
				<td><?php echo Presenter::status_badge( $wpsl_report['status'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped inside Presenter. ?></td>
				<td>
					<?php if ( '' !== $wpsl_report['failure_reason'] ) : ?>
						<p><?php echo esc_html( $wpsl_report['failure_reason'] ); ?></p>
					<?php endif; ?>
					<?php if ( ! empty( $wpsl_report['verification']['detail'] ) && in_array( $wpsl_report['verification']['status'], array( 'unverified', 'failed' ), true ) ) : ?>
						<p><?php echo esc_html( $wpsl_report['verification']['detail'] ); ?></p>
					<?php endif; ?>
					<?php if ( '' !== $wpsl_report['manual_action'] ) : ?>
						<p><?php echo wp_kses( Presenter::requires_tag( 'manual' ), array( 'span' => array( 'class' => true ) ) ); ?> <?php echo esc_html( $wpsl_report['manual_action'] ); ?></p>
					<?php endif; ?>
				</td>
			</tr>
		<?php endforeach; ?>
		</tbody>
	</table>
	</div>
<?php endif; ?>

<h2><?php esc_html_e( 'Open findings outside the plugin\'s reach', 'wp-security-lockdown' ); ?></h2>
<?php if ( ! $wpsl_open ) : ?>
	<p><?php esc_html_e( 'No open findings.', 'wp-security-lockdown' ); ?></p>
<?php else : ?>
	<ul class="wpsl-plain">
		<?php foreach ( array_slice( $wpsl_open, 0, 6 ) as $wpsl_row ) : ?>
			<li><?php echo Presenter::check_badge( $wpsl_row['status'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped inside Presenter. ?> <strong><?php echo esc_html( $wpsl_row['title'] ); ?></strong> &mdash; <?php echo esc_html( $wpsl_row['summary'] ); ?></li>
		<?php endforeach; ?>
	</ul>
	<p><a href="<?php echo esc_url( \WP_Security_Lockdown\Admin\Admin::url( 'checks' ) ); ?>">
		<?php
		printf(
			/* translators: %d: total number of open findings. */
			esc_html__( 'See all %d findings and what to do about them', 'wp-security-lockdown' ),
			(int) count( $wpsl_open )
		);
		?>
	</a></p>
<?php endif; ?>

<h2><?php esc_html_e( 'How to read the statuses', 'wp-security-lockdown' ); ?></h2>
<ul class="wpsl-legend">
	<li><?php echo Presenter::status_badge( Policy_Manager::VERIFIED_HTTP ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?> <?php esc_html_e( 'A real request to this site showed the intended effect.', 'wp-security-lockdown' ); ?></li>
	<li><?php echo Presenter::status_badge( Policy_Manager::VERIFIED_LOCAL ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?> <?php esc_html_e( 'The logic was tested inside PHP (hooks and filters behave as intended). This is weaker than an HTTP test and is only used where it is sufficient.', 'wp-security-lockdown' ); ?></li>
	<li><?php echo Presenter::status_badge( Policy_Manager::UNVERIFIED ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?> <?php esc_html_e( 'The hooks are in place but no test has proven the effect (or the policy changed since). Not counted as protection.', 'wp-security-lockdown' ); ?></li>
	<li><?php echo Presenter::status_badge( Policy_Manager::PARTIAL ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?> <?php esc_html_e( 'Part of the control is in place; something is missing or overridden.', 'wp-security-lockdown' ); ?></li>
	<li><?php echo Presenter::status_badge( Policy_Manager::NOT_WORKING ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?> <?php esc_html_e( 'A test ran and showed the control is not having its effect.', 'wp-security-lockdown' ); ?></li>
</ul>
