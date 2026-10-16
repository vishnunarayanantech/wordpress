<?php
/**
 * Dashboard shell: heading, notice, tabs.
 *
 * @package WP_Security_Lockdown
 * @var array $view Template data (see Admin::render()).
 */

defined( 'ABSPATH' ) || exit;

use WP_Security_Lockdown\Admin\Admin;

$wpsl_tabs = array(
	'overview' => __( 'Overview', 'wp-security-lockdown' ),
	'controls' => __( 'Controls', 'wp-security-lockdown' ),
	'checks'   => __( 'Checks', 'wp-security-lockdown' ),
	'settings' => __( 'Policy settings', 'wp-security-lockdown' ),
	'audit'    => __( 'Audit log', 'wp-security-lockdown' ),
	'rollback' => __( 'Rollback and recovery', 'wp-security-lockdown' ),
);
?>
<div class="wrap wp-security-lockdown">
	<h1><?php esc_html_e( 'WP Security Lockdown', 'wp-security-lockdown' ); ?></h1>

	<?php if ( ! empty( $view['notice'] ) ) : ?>
		<div class="notice notice-<?php echo esc_attr( $view['notice'][0] ); ?> is-dismissible"><p><?php echo esc_html( $view['notice'][1] ); ?></p></div>
	<?php endif; ?>

	<nav class="nav-tab-wrapper" aria-label="<?php esc_attr_e( 'Sections', 'wp-security-lockdown' ); ?>">
		<?php foreach ( $wpsl_tabs as $wpsl_slug => $wpsl_label ) : ?>
			<a class="nav-tab<?php echo $wpsl_slug === $view['tab'] ? ' nav-tab-active' : ''; ?>"
				href="<?php echo esc_url( Admin::url( $wpsl_slug ) ); ?>"
				<?php echo $wpsl_slug === $view['tab'] ? 'aria-current="page"' : ''; ?>><?php echo esc_html( $wpsl_label ); ?></a>
		<?php endforeach; ?>
	</nav>

	<?php $view['admin']->include_view( 'tab-' . $view['tab'], $view ); ?>
</div>
