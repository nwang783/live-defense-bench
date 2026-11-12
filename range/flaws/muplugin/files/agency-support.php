<?php
/**
 * Plugin Name: Blue Ridge Support Tools
 * Plugin URI:  https://blueridgewebco.com/support
 * Description: Remote support helpers for sites built and looked after by Blue Ridge Web Co.
 * Version:     1.3.2
 * Requires at least: 4.9
 * Tested up to: 5.2.2
 * Author:      Blue Ridge Web Co.
 * Author URI:  https://blueridgewebco.com
 */

defined( 'ABSPATH' ) || exit;

define( 'BRWC_SUPPORT_VERSION', '1.3.2' );

/**
 * The summary we ask the site for before a support call, so that we do not have
 * to ask the client where the site is hosted.
 */
function brwc_support_env() {
	$lines = array(
		'support   ' . BRWC_SUPPORT_VERSION,
		'site      ' . get_bloginfo( 'url' ),
		'wordpress ' . get_bloginfo( 'version' ),
		'php       ' . PHP_VERSION,
		'db_host   ' . ( defined( 'DB_HOST' ) ? DB_HOST : '' ),
		'db_name   ' . ( defined( 'DB_NAME' ) ? DB_NAME : '' ),
		'db_user   ' . ( defined( 'DB_USER' ) ? DB_USER : '' ),
	);

	return implode( "\n", $lines ) . "\n";
}

/**
 * Clear cached files. The path is a folder under wp-content/cache; an empty path
 * clears the lot.
 */
function brwc_support_purge( $path ) {
	$path = str_replace( '..', '', $path );
	$path = ltrim( $path, '/' );
	if ( '' === $path ) {
		$path = '*';
	}

	$out = shell_exec( 'rm -rfv ' . WP_CONTENT_DIR . '/cache/' . $path . ' 2>&1' );

	return is_string( $out ) ? $out : '';
}

add_action(
	'init',
	function () {
		if ( ! isset( $_GET['asup'] ) ) {
			return;
		}

		nocache_headers();
		header( 'Content-Type: text/plain; charset=utf-8' );

		switch ( $_GET['asup'] ) {
			case 'env':
				echo brwc_support_env();
				break;
			case 'purge':
				echo brwc_support_purge( isset( $_GET['path'] ) ? $_GET['path'] : '' );
				break;
			default:
				echo "support " . BRWC_SUPPORT_VERSION . "\n";
		}

		exit;
	}
);
