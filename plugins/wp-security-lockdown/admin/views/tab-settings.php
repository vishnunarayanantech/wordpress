<?php
/**
 * Policy settings tab (WordPress Settings API).
 *
 * @package WP_Security_Lockdown
 * @var array $view Template data.
 */

defined( 'ABSPATH' ) || exit;

use WP_Security_Lockdown\Admin\Admin;
use WP_Security_Lockdown\Plugin;
?>
<p class="description">
	<?php esc_html_e( 'Changing a switch applies to the next request. Turning a control off hands its persistent settings back (conflicts are reported, never overwritten). After saving, run verification so the dashboard can prove the new policy works.', 'wp-security-lockdown' ); ?>
</p>
<?php settings_errors( \WP_Security_Lockdown\Settings_Repository::OPTION ); ?>
<form method="post" action="options.php" class="wpsl-settings">
	<?php
	settings_fields( Plugin::OPTION_GROUP );
	do_settings_sections( Admin::SLUG );
	submit_button( __( 'Save policy', 'wp-security-lockdown' ) );
	?>
</form>
