<?php
/**
 * Controls tab: every control with its configured policy, effective state and verification.
 *
 * @package WP_Security_Lockdown
 * @var array $view Template data.
 */

defined( 'ABSPATH' ) || exit;

use WP_Security_Lockdown\Admin\Presenter;
use WP_Security_Lockdown\Policy_Manager;
?>
<p class="description">
	<?php esc_html_e( 'Configured = the policy says it should be on. Enforced = the hooks or options are in place right now. Verified = a test showed the intended effect. Only "Verified" means a control is known to work.', 'wp-security-lockdown' ); ?>
</p>

<?php foreach ( $view['reports'] as $wpsl_report ) : ?>
	<?php $wpsl_v = $wpsl_report['verification']; ?>
	<section class="wpsl-control" aria-labelledby="wpsl-c-<?php echo esc_attr( $wpsl_report['id'] ); ?>">
		<header>
			<h2 id="wpsl-c-<?php echo esc_attr( $wpsl_report['id'] ); ?>"><?php echo esc_html( $wpsl_report['title'] ); ?></h2>
			<?php echo Presenter::status_badge( $wpsl_report['status'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped inside Presenter. ?>
			<?php if ( '' !== $wpsl_report['manual_action'] ) : ?>
				<?php echo wp_kses( Presenter::requires_tag( 'manual' ), array( 'span' => array( 'class' => true ) ) ); ?>
			<?php endif; ?>
			<?php if ( $wpsl_report['server_level'] ) : ?>
				<?php echo wp_kses( Presenter::requires_tag( 'server' ), array( 'span' => array( 'class' => true ) ) ); ?>
			<?php endif; ?>
		</header>
		<p><?php echo esc_html( $wpsl_report['description'] ); ?></p>

		<table class="widefat striped wpsl-table">
			<tbody>
				<tr>
					<th scope="row"><?php esc_html_e( 'Control identifier', 'wp-security-lockdown' ); ?></th>
					<td><code><?php echo esc_html( $wpsl_report['id'] ); ?></code></td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Configured', 'wp-security-lockdown' ); ?></th>
					<td><?php echo $wpsl_report['enabled'] ? esc_html__( 'Yes (policy switched on)', 'wp-security-lockdown' ) : esc_html__( 'No (disabled in the policy settings)', 'wp-security-lockdown' ); ?></td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Desired policy', 'wp-security-lockdown' ); ?></th>
					<td><?php echo esc_html( $wpsl_report['desired'] ); ?></td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Effective state (this request)', 'wp-security-lockdown' ); ?></th>
					<td><code><?php echo esc_html( $wpsl_report['state'] ); ?></code>
						<?php if ( '' !== $wpsl_report['failure_reason'] ) : ?>
							<p><?php echo esc_html( $wpsl_report['failure_reason'] ); ?></p>
						<?php endif; ?>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Enforcement method', 'wp-security-lockdown' ); ?></th>
					<td>
						<?php if ( $wpsl_report['enforcement'] ) : ?>
							<ul class="wpsl-plain">
								<?php foreach ( $wpsl_report['enforcement'] as $wpsl_line ) : ?>
									<li><?php echo esc_html( $wpsl_line ); ?></li>
								<?php endforeach; ?>
							</ul>
						<?php else : ?>
							&ndash;
						<?php endif; ?>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Survives deactivation?', 'wp-security-lockdown' ); ?></th>
					<td><?php echo '' === $wpsl_report['persists'] ? esc_html__( 'No: stops immediately when the plugin is deactivated.', 'wp-security-lockdown' ) : esc_html( $wpsl_report['persists'] ); ?></td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Verification', 'wp-security-lockdown' ); ?></th>
					<td>
						<?php if ( 'not_applicable' === $wpsl_v['status'] ) : ?>
							&ndash;
						<?php else : ?>
							<strong><?php echo esc_html( ucfirst( $wpsl_v['status'] ) ); ?></strong>
							(<?php echo esc_html( Presenter::method_label( $wpsl_v['method'] ) ); ?>)
							<?php if ( $wpsl_v['time'] ) : ?>
								<?php
								printf(
									/* translators: %s: how long ago. */
									esc_html__( '&mdash; checked %s', 'wp-security-lockdown' ),
									esc_html( Presenter::when( $wpsl_v['time'] ) )
								);
								?>
							<?php endif; ?>
							<?php if ( '' !== $wpsl_v['detail'] ) : ?>
								<p><?php echo esc_html( $wpsl_v['detail'] ); ?></p>
							<?php endif; ?>
						<?php endif; ?>
					</td>
				</tr>
				<?php if ( '' !== $wpsl_report['manual_action'] ) : ?>
					<tr>
						<th scope="row"><?php esc_html_e( 'Manual action required', 'wp-security-lockdown' ); ?></th>
						<td><?php echo esc_html( $wpsl_report['manual_action'] ); ?></td>
					</tr>
				<?php endif; ?>
				<?php if ( $wpsl_report['warnings'] ) : ?>
					<tr>
						<th scope="row"><?php esc_html_e( 'Compatibility warnings', 'wp-security-lockdown' ); ?></th>
						<td>
							<ul class="wpsl-plain">
								<?php foreach ( $wpsl_report['warnings'] as $wpsl_line ) : ?>
									<li><?php echo esc_html( $wpsl_line ); ?></li>
								<?php endforeach; ?>
							</ul>
						</td>
					</tr>
				<?php endif; ?>
			</tbody>
		</table>

		<?php if ( $wpsl_report['details'] ) : ?>
			<details>
				<summary><?php esc_html_e( 'Sub-checks', 'wp-security-lockdown' ); ?></summary>
				<table class="widefat striped wpsl-table">
					<tbody>
					<?php foreach ( $wpsl_report['details'] as $wpsl_detail ) : ?>
						<tr>
							<td><?php echo Presenter::check_badge( $wpsl_detail['status'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped inside Presenter. ?></td>
							<td><code><?php echo esc_html( $wpsl_detail['label'] ); ?></code></td>
							<td><?php echo esc_html( $wpsl_detail['text'] ); ?></td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
			</details>
		<?php endif; ?>
	</section>
<?php endforeach; ?>
