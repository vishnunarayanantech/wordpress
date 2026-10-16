<?php
/**
 * Audit log tab.
 *
 * @package WP_Security_Lockdown
 * @var array $view Template data.
 */

defined( 'ABSPATH' ) || exit;

use WP_Security_Lockdown\Admin\Presenter;
?>
<p class="description">
	<?php
	printf(
		/* translators: %d: maximum number of retained entries. */
		esc_html__( 'The newest %d events are kept; older ones are overwritten. The log is never emptied by deactivating or uninstalling the plugin, and it never contains passwords, cookies, tokens or user names. Client addresses are stored anonymized.', 'wp-security-lockdown' ),
		(int) $view['plugin']->logger()->max_entries()
	);
	?>
</p>

<?php if ( empty( $view['entries'] ) ) : ?>
	<p><?php esc_html_e( 'No events have been recorded yet.', 'wp-security-lockdown' ); ?></p>
<?php else : ?>
	<table class="widefat striped wpsl-table">
		<caption class="screen-reader-text"><?php esc_html_e( 'Audit log, newest first', 'wp-security-lockdown' ); ?></caption>
		<thead><tr>
			<th scope="col"><?php esc_html_e( 'When', 'wp-security-lockdown' ); ?></th>
			<th scope="col"><?php esc_html_e( 'Level', 'wp-security-lockdown' ); ?></th>
			<th scope="col"><?php esc_html_e( 'Event', 'wp-security-lockdown' ); ?></th>
			<th scope="col"><?php esc_html_e( 'Message', 'wp-security-lockdown' ); ?></th>
			<th scope="col"><?php esc_html_e( 'Details', 'wp-security-lockdown' ); ?></th>
		</tr></thead>
		<tbody>
		<?php foreach ( $view['entries'] as $wpsl_entry ) : ?>
			<?php $wpsl_level = isset( $wpsl_entry['l'] ) ? $wpsl_entry['l'] : 'info'; ?>
			<tr>
				<td><?php echo esc_html( wp_date( 'Y-m-d H:i:s', (int) ( $wpsl_entry['t'] ?? 0 ) ) ); ?></td>
				<td><?php echo Presenter::check_badge( 'error' === $wpsl_level ? 'fail' : ( 'warning' === $wpsl_level ? 'warn' : 'info' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped inside Presenter. ?></td>
				<td><code><?php echo esc_html( $wpsl_entry['e'] ?? '' ); ?></code></td>
				<td><?php echo esc_html( $wpsl_entry['m'] ?? '' ); ?></td>
				<td><?php echo Presenter::context( $wpsl_entry['c'] ?? array() ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped inside Presenter. ?></td>
			</tr>
		<?php endforeach; ?>
		</tbody>
	</table>
<?php endif; ?>
