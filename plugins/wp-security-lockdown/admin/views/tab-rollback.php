<?php
/**
 * Rollback and recovery tab.
 *
 * @package WP_Security_Lockdown
 * @var array $view Template data.
 */

defined( 'ABSPATH' ) || exit;

use WP_Security_Lockdown\Admin\Presenter;
use WP_Security_Lockdown\Rollback;

$wpsl_status_text = array(
	Rollback::RESTORED        => __( 'Restored', 'wp-security-lockdown' ),
	Rollback::RESTORED_FORCED => __( 'Restored (forced over a newer change)', 'wp-security-lockdown' ),
	Rollback::NOTHING         => __( 'Nothing to restore (the plugin never changed it)', 'wp-security-lockdown' ),
	Rollback::CONFLICT        => __( 'NOT restored: changed after the plugin set it', 'wp-security-lockdown' ),
	Rollback::FAILED          => __( 'NOT restored: the update failed', 'wp-security-lockdown' ),
	Rollback::NOT_MANAGED     => __( 'Not managed by the plugin', 'wp-security-lockdown' ),
);
$wpsl_sync_text   = array(
	'in_sync'   => __( 'Unchanged since the plugin set it: can be restored safely', 'wp-security-lockdown' ),
	'drifted'   => __( 'Changed since the plugin set it: restoring would overwrite a newer change (conflict)', 'wp-security-lockdown' ),
	'untouched' => __( 'Already had the policy value: the plugin changed nothing', 'wp-security-lockdown' ),
);
?>
<h2><?php esc_html_e( 'Settings the plugin changed', 'wp-security-lockdown' ); ?></h2>
<p class="description"><?php esc_html_e( 'Only options the plugin actually changed are recorded, with the value they had before. Nothing else on your site is snapshotted or touched.', 'wp-security-lockdown' ); ?></p>

<?php if ( empty( $view['ledger'] ) ) : ?>
	<p><?php esc_html_e( 'The plugin currently owns no persistent setting.', 'wp-security-lockdown' ); ?></p>
<?php else : ?>
	<table class="widefat striped wpsl-table">
		<caption class="screen-reader-text"><?php esc_html_e( 'Options changed by the plugin', 'wp-security-lockdown' ); ?></caption>
		<thead><tr>
			<th scope="col"><?php esc_html_e( 'Option', 'wp-security-lockdown' ); ?></th>
			<th scope="col"><?php esc_html_e( 'Original value', 'wp-security-lockdown' ); ?></th>
			<th scope="col"><?php esc_html_e( 'Value set by the plugin', 'wp-security-lockdown' ); ?></th>
			<th scope="col"><?php esc_html_e( 'Current value', 'wp-security-lockdown' ); ?></th>
			<th scope="col"><?php esc_html_e( 'State', 'wp-security-lockdown' ); ?></th>
		</tr></thead>
		<tbody>
		<?php foreach ( $view['ledger'] as $wpsl_row ) : ?>
			<tr>
				<td><code><?php echo esc_html( $wpsl_row['option'] ); ?></code><br /><small><?php echo esc_html( $wpsl_row['control'] ); ?></small></td>
				<td><?php echo Presenter::option_value( $wpsl_row['original'], ! $wpsl_row['existed'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped inside Presenter. ?></td>
				<td><?php echo Presenter::option_value( $wpsl_row['applied'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped inside Presenter. ?></td>
				<td><?php echo Presenter::option_value( $wpsl_row['current'], $wpsl_row['absent'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped inside Presenter. ?></td>
				<td><?php echo esc_html( isset( $wpsl_sync_text[ $wpsl_row['sync'] ] ) ? $wpsl_sync_text[ $wpsl_row['sync'] ] : $wpsl_row['sync'] ); ?></td>
			</tr>
		<?php endforeach; ?>
		</tbody>
	</table>

	<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="wpsl-rollback">
		<input type="hidden" name="action" value="wp_security_lockdown_rollback" />
		<?php wp_nonce_field( 'wp_security_lockdown_rollback' ); ?>
		<p>
			<label>
				<input type="checkbox" name="force" value="1" />
				<?php esc_html_e( 'Also overwrite values that were changed after the plugin set them (not recommended: this discards a newer change).', 'wp-security-lockdown' ); ?>
			</label>
		</p>
		<?php submit_button( __( 'Roll back plugin-owned changes', 'wp-security-lockdown' ), 'delete', 'submit', false ); ?>
		<p class="description"><?php esc_html_e( 'Restores the original values. A control whose settings were all handed back is switched off in the policy so that it does not re-apply them; runtime protections of controls that keep their settings stay active. Conflicts are listed, never silently overwritten.', 'wp-security-lockdown' ); ?></p>
	</form>
<?php endif; ?>

<?php if ( ! empty( $view['detail']['results'] ) ) : ?>
	<h3><?php esc_html_e( 'Result of the last rollback', 'wp-security-lockdown' ); ?></h3>
	<table class="widefat striped wpsl-table">
		<thead><tr>
			<th scope="col"><?php esc_html_e( 'Option', 'wp-security-lockdown' ); ?></th>
			<th scope="col"><?php esc_html_e( 'Outcome', 'wp-security-lockdown' ); ?></th>
		</tr></thead>
		<tbody>
		<?php foreach ( $view['detail']['results'] as $wpsl_result ) : ?>
			<tr>
				<td><code><?php echo esc_html( $wpsl_result['option'] ); ?></code></td>
				<td><?php echo esc_html( isset( $wpsl_status_text[ $wpsl_result['status'] ] ) ? $wpsl_status_text[ $wpsl_result['status'] ] : $wpsl_result['status'] ); ?></td>
			</tr>
		<?php endforeach; ?>
		</tbody>
	</table>
	<?php if ( ! empty( $view['detail']['disabled'] ) ) : ?>
		<p><?php echo esc_html( sprintf( /* translators: %s: control identifiers. */ __( 'Controls switched off in the policy: %s', 'wp-security-lockdown' ), implode( ', ', array_map( 'sanitize_key', $view['detail']['disabled'] ) ) ) ); ?></p>
	<?php endif; ?>
<?php endif; ?>

<h2><?php esc_html_e( 'What happens when you deactivate or uninstall', 'wp-security-lockdown' ); ?></h2>
<table class="widefat striped wpsl-table">
	<tbody>
		<tr>
			<th scope="row"><?php esc_html_e( 'Stops immediately on deactivation', 'wp-security-lockdown' ); ?></th>
			<td><?php esc_html_e( 'Every runtime protection: comment and ping filters, XML-RPC rejection, the REST access policy, login rate limiting and lockouts, author / version / discovery hygiene, the generic login messages, the password-length rule, and the file-editor block. The site behaves as if the plugin had never been installed, except for the persistent options below.', 'wp-security-lockdown' ); ?></td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'Stays in the database', 'wp-security-lockdown' ); ?></th>
			<td><?php esc_html_e( 'The discussion defaults for new content (default_comment_status, default_ping_status, default_pingback_flag) stay as set until rolled back, plus the policy settings, the change record above and the audit log. Deactivation never deletes the audit log or any site content.', 'wp-security-lockdown' ); ?></td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'Uninstalling (deleting) the plugin', 'wp-security-lockdown' ); ?></th>
			<td><?php esc_html_e( 'Removes the policy settings, temporary lockout counters and scheduled events. It keeps the audit log and the change record so original values remain recoverable. It never deletes content, users, comments, uploads, plugins or themes.', 'wp-security-lockdown' ); ?></td>
		</tr>
	</tbody>
</table>

<h2><?php esc_html_e( 'Recovery if the plugin ever locks you out or breaks the site', 'wp-security-lockdown' ); ?></h2>
<p><?php esc_html_e( 'These work without the dashboard. Use the first one that applies:', 'wp-security-lockdown' ); ?></p>
<ol class="wpsl-recovery">
	<li><strong><?php esc_html_e( 'Locked out by the login limiter:', 'wp-security-lockdown' ); ?></strong> <?php esc_html_e( 'wait for the block to expire (default 15 minutes), try another network, or add this line to wp-config.php:', 'wp-security-lockdown' ); ?> <code>define( 'WP_SECURITY_LOCKDOWN_DISABLE_LOGIN_LIMITER', true );</code></li>
	<li><strong><?php esc_html_e( 'Switch the whole plugin off without touching files:', 'wp-security-lockdown' ); ?></strong> <code>define( 'WP_SECURITY_LOCKDOWN_DISABLE', true );</code> <?php esc_html_e( '(in wp-config.php, above the line that says "That\'s all, stop editing!"). Nothing from the plugin runs and nothing stored is changed.', 'wp-security-lockdown' ); ?></li>
	<li><strong><?php esc_html_e( 'Fatal error / white screen:', 'wp-security-lockdown' ); ?></strong> <?php esc_html_e( 'over SFTP/SSH rename the folder wp-content/plugins/wp-security-lockdown to wp-security-lockdown.off. WordPress deactivates the missing plugin automatically.', 'wp-security-lockdown' ); ?> <code>mv wp-content/plugins/wp-security-lockdown wp-content/plugins/wp-security-lockdown.off</code></li>
	<li><strong>WP-CLI:</strong> <code>wp plugin deactivate wp-security-lockdown</code></li>
	<li><strong><?php esc_html_e( 'Undo the persistent options by hand:', 'wp-security-lockdown' ); ?></strong> <?php esc_html_e( 'Settings > Discussion, or use the table above after the dashboard is reachable again.', 'wp-security-lockdown' ); ?></li>
</ol>
