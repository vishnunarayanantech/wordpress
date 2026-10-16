<?php
/**
 * Checks tab: findings that need a person or the server, compatibility warnings, enforcement boundary.
 *
 * @package WP_Security_Lockdown
 * @var array $view Template data.
 */

defined( 'ABSPATH' ) || exit;

use WP_Security_Lockdown\Admin\Presenter;
use WP_Security_Lockdown\Health_Check;
use WP_Security_Lockdown\Policy_Manager;
use WP_Security_Lockdown\Security_Headers_Audit;

$wpsl_rows   = $view['checks']['rows'];
$wpsl_groups = Health_Check::groups();
$wpsl_sum    = Health_Check::summarize( $wpsl_rows );

$wpsl_header_rows = array_values(
	array_filter(
		$wpsl_rows,
		static function ( $row ) {
			return 'headers' === $row['group'];
		}
	)
);
$wpsl_snippets    = Security_Headers_Audit::snippets( $wpsl_header_rows );

$wpsl_warnings = array();
foreach ( $view['reports'] as $wpsl_report ) {
	if ( Policy_Manager::DISABLED === $wpsl_report['status'] ) {
		continue;
	}
	foreach ( $wpsl_report['warnings'] as $wpsl_warning ) {
		$wpsl_warnings[] = array( $wpsl_report['title'], $wpsl_warning );
	}
}
?>
<p>
	<?php
	printf(
		/* translators: 1: number of problems, 2: warnings, 3: manual actions, 4: server-level actions. */
		esc_html__( 'Problems: %1$d. Warnings: %2$d. Need a manual action: %3$d. Need server-level configuration: %4$d.', 'wp-security-lockdown' ),
		(int) $wpsl_sum['fail'],
		(int) $wpsl_sum['warn'],
		(int) $wpsl_sum['manual'],
		(int) $wpsl_sum['server']
	);
	?>
	<?php
	printf(
		/* translators: %s: when the deep diagnostics last ran. */
		esc_html__( 'Deep diagnostics last ran: %s.', 'wp-security-lockdown' ),
		esc_html( Presenter::when( $view['checks']['deep_time'] ) )
	);
	?>
</p>

<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
	<input type="hidden" name="action" value="wp_security_lockdown_verify" />
	<?php wp_nonce_field( 'wp_security_lockdown_verify' ); ?>
	<?php submit_button( __( 'Run verification and diagnostics', 'wp-security-lockdown' ), 'primary', 'submit', false ); ?>
	<span class="description"><?php esc_html_e( 'Checks marked "run diagnostics" and the headers, exposure and uploads findings need this.', 'wp-security-lockdown' ); ?></span>
</form>

<?php foreach ( $wpsl_groups as $wpsl_slug => $wpsl_label ) : ?>
	<?php
	$wpsl_group_rows = array_values(
		array_filter(
			$wpsl_rows,
			static function ( $row ) use ( $wpsl_slug ) {
				return $row['group'] === $wpsl_slug;
			}
		)
	);
	if ( ! $wpsl_group_rows ) {
		continue;
	}
	?>
	<h2><?php echo esc_html( $wpsl_label ); ?></h2>
	<div class="wpsl-scroll">
	<table class="widefat striped wpsl-table">
		<caption class="screen-reader-text"><?php echo esc_html( $wpsl_label ); ?></caption>
		<thead><tr>
			<th scope="col"><?php esc_html_e( 'Result', 'wp-security-lockdown' ); ?></th>
			<th scope="col"><?php esc_html_e( 'Check', 'wp-security-lockdown' ); ?></th>
			<th scope="col"><?php esc_html_e( 'Finding and what to do', 'wp-security-lockdown' ); ?></th>
		</tr></thead>
		<tbody>
		<?php foreach ( $wpsl_group_rows as $wpsl_row ) : ?>
			<tr>
				<td><?php echo Presenter::check_badge( $wpsl_row['status'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped inside Presenter. ?></td>
				<td>
					<strong><?php echo esc_html( $wpsl_row['title'] ); ?></strong>
					<?php echo wp_kses( Presenter::requires_tag( in_array( $wpsl_row['status'], array( 'warn', 'fail' ), true ) ? $wpsl_row['requires'] : '' ), array( 'span' => array( 'class' => true ) ) ); ?>
				</td>
				<td>
					<p><?php echo esc_html( $wpsl_row['summary'] ); ?></p>
					<?php if ( '' !== $wpsl_row['remediation'] ) : ?>
						<p class="wpsl-todo"><strong><?php esc_html_e( 'To do:', 'wp-security-lockdown' ); ?></strong> <?php echo esc_html( $wpsl_row['remediation'] ); ?></p>
					<?php endif; ?>
				</td>
			</tr>
		<?php endforeach; ?>
		</tbody>
	</table>
	</div>
<?php endforeach; ?>

<?php if ( '' !== $wpsl_snippets['apache'] ) : ?>
	<h3><?php esc_html_e( 'Suggested header configuration (review before using)', 'wp-security-lockdown' ); ?></h3>
	<p class="description"><?php esc_html_e( 'These only contain the headers that are safe on practically every site. Content-Security-Policy is intentionally left out: build it with Report-Only first.', 'wp-security-lockdown' ); ?></p>
	<details>
		<summary>Apache (.htaccess or virtual host, needs mod_headers)</summary>
		<pre class="wpsl-code"><?php echo esc_html( $wpsl_snippets['apache'] ); ?></pre>
	</details>
	<details>
		<summary>nginx (server block)</summary>
		<pre class="wpsl-code"><?php echo esc_html( $wpsl_snippets['nginx'] ); ?></pre>
	</details>
<?php endif; ?>

<h2><?php esc_html_e( 'Compatibility warnings', 'wp-security-lockdown' ); ?></h2>
<?php if ( ! $wpsl_warnings ) : ?>
	<p><?php esc_html_e( 'No compatibility warnings for the enabled controls.', 'wp-security-lockdown' ); ?></p>
<?php else : ?>
	<ul class="wpsl-plain">
		<?php foreach ( $wpsl_warnings as $wpsl_pair ) : ?>
			<li><strong><?php echo esc_html( $wpsl_pair[0] ); ?>:</strong> <?php echo esc_html( $wpsl_pair[1] ); ?></li>
		<?php endforeach; ?>
	</ul>
<?php endif; ?>

<h2><?php esc_html_e( 'What a plugin can and cannot enforce', 'wp-security-lockdown' ); ?></h2>
<div class="wpsl-scroll">
<table class="widefat striped wpsl-table">
	<thead><tr>
		<th scope="col"><?php esc_html_e( 'Protection', 'wp-security-lockdown' ); ?></th>
		<th scope="col"><?php esc_html_e( 'Where it must be configured', 'wp-security-lockdown' ); ?></th>
	</tr></thead>
	<tbody>
		<tr><td><?php esc_html_e( 'Comments closed, XML-RPC rejected, REST access policy, login rate limiting, user enumeration, version / discovery hygiene, code editor off, password length', 'wp-security-lockdown' ); ?></td><td><strong><?php esc_html_e( 'This plugin (PHP).', 'wp-security-lockdown' ); ?></strong> <?php esc_html_e( 'Effective only while the plugin is active; it cannot protect requests that never reach PHP (static files).', 'wp-security-lockdown' ); ?></td></tr>
		<tr><td><?php esc_html_e( 'HSTS, Content-Security-Policy, X-Frame-Options, Referrer-Policy, Permissions-Policy', 'wp-security-lockdown' ); ?></td><td><?php esc_html_e( 'Apache / nginx / CDN. Audited here, not enforced: headers set by PHP miss static files and error pages.', 'wp-security-lockdown' ); ?></td></tr>
		<tr><td><?php esc_html_e( 'Denying readme.html, license.txt, .git, backups, directory listings', 'wp-security-lockdown' ); ?></td><td><?php esc_html_e( 'Web server rules.', 'wp-security-lockdown' ); ?></td></tr>
		<tr><td><?php esc_html_e( 'No PHP execution in uploads', 'wp-security-lockdown' ); ?></td><td><?php esc_html_e( 'Web server / PHP-FPM configuration.', 'wp-security-lockdown' ); ?></td></tr>
		<tr><td><?php esc_html_e( 'File ownership and permissions, wp-config.php mode', 'wp-security-lockdown' ); ?></td><td><?php esc_html_e( 'The filesystem / host. The plugin never changes ownership or permissions.', 'wp-security-lockdown' ); ?></td></tr>
		<tr><td><?php esc_html_e( 'display_errors for errors raised before plugins load, expose_php, PHP version', 'wp-security-lockdown' ); ?></td><td><?php esc_html_e( 'php.ini / PHP-FPM pool / host.', 'wp-security-lockdown' ); ?></td></tr>
		<tr><td><?php esc_html_e( 'HTTPS and HTTP to HTTPS redirect', 'wp-security-lockdown' ); ?></td><td><?php esc_html_e( 'Web server / CDN.', 'wp-security-lockdown' ); ?></td></tr>
		<tr><td><?php esc_html_e( 'Database account privileges', 'wp-security-lockdown' ); ?></td><td><?php esc_html_e( 'MySQL administration and wp-config.php (edited by you).', 'wp-security-lockdown' ); ?></td></tr>
		<tr><td><?php esc_html_e( 'Multifactor authentication', 'wp-security-lockdown' ); ?></td><td><?php esc_html_e( 'A dedicated MFA plugin. This plugin only reports whether one is present; it never claims MFA is enforced.', 'wp-security-lockdown' ); ?></td></tr>
		<tr><td><?php esc_html_e( 'Network-level blocking of repeat attackers', 'wp-security-lockdown' ); ?></td><td><?php esc_html_e( 'fail2ban, a WAF or the CDN.', 'wp-security-lockdown' ); ?></td></tr>
	</tbody>
</table>
</div>
