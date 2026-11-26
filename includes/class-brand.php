<?php
/**
 * Bee Monitor brand mark: an original geometric bee (GPL-2.0-or-later, part of this plugin).
 *
 * Three variants: a line mark that matches the interface icons, a hexagon badge for the
 * page header, and a solid silhouette for the admin menu (WordPress recolors its fill).
 *
 * @package BeeMonitor
 */

namespace BeeMonitor;

defined( 'ABSPATH' ) || exit;

/**
 * Brand assets.
 */
final class Brand {

	const MARK = '<path d="M9.2 10.4C6.6 10 4 8.3 3.8 6.2 3.6 4.3 6.3 4.1 8.1 6c1.1 1.2 1.5 2.6 1.6 3.4"></path><path d="M14.8 10.4c2.6-.4 5.2-2.1 5.4-4.2.2-1.9-2.5-2.1-4.3-.2-1.1 1.2-1.5 2.6-1.6 3.4"></path><circle cx="12" cy="6.4" r="2"></circle><ellipse cx="12" cy="14.8" rx="4" ry="5.6"></ellipse><path d="M8.4 13.2h7.2M8.6 16.6h6.8"></path>';

	const HEX = 'M24 2.5c.9 0 1.8.2 2.6.7l15.2 8.8c1.6.9 2.6 2.6 2.6 4.5v15c0 1.9-1 3.6-2.6 4.5l-15.2 8.8c-1.6.9-3.6.9-5.2 0L6.2 36c-1.6-.9-2.6-2.6-2.6-4.5v-15c0-1.9 1-3.6 2.6-4.5l15.2-8.8c.8-.5 1.7-.7 2.6-.7z';

	/**
	 * Hexagon badge: amber line bee on charcoal.
	 *
	 * @param int    $size    Pixels.
	 * @param string $label   Accessible name; empty marks it decorative.
	 * @param bool   $on_dark Outline the hexagon so it stays visible on dark backgrounds.
	 * @return string
	 */
	public static function badge( $size = 36, $label = '', $on_dark = false ) {
		$size = max( 16, min( 128, (int) $size ) );
		$hex  = $on_dark ? '<path fill="#2A3646" stroke="#F5B301" stroke-opacity=".7" stroke-width="1.5" d="' . self::HEX . '"></path>' : '<path fill="#1D2733" d="' . self::HEX . '"></path>';
		return '<svg class="bee-monitor-logo" width="' . $size . '" height="' . $size . '" viewBox="0 0 48 48" ' . self::a11y( $label ) . '>' . $hex . '<g transform="translate(9.6 9.6) scale(1.2)" fill="none" stroke="#F5B301" stroke-width="1.85" stroke-linecap="round" stroke-linejoin="round">' . self::MARK . '</g></svg>';
	}

	/**
	 * Line mark in the current text color, matching the 24px interface icons.
	 *
	 * @param int    $size  Pixels.
	 * @param string $label Accessible name; empty marks it decorative.
	 * @return string
	 */
	public static function mark( $size = 16, $label = '' ) {
		$size = max( 12, min( 128, (int) $size ) );
		return '<svg class="bee-monitor-icon bee-monitor-mark" width="' . $size . '" height="' . $size . '" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" ' . self::a11y( $label ) . '>' . self::MARK . '</svg>';
	}

	/**
	 * Admin menu icon (solid shapes only, so WordPress can recolor it for every admin color scheme).
	 *
	 * @return string data: URI.
	 */
	public static function menu_icon() {
		$svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path fill="black" fill-opacity=".55" d="M9.9 10.8C6.8 10.6 3.2 8.7 2.9 6.2c-.3-2.6 3.1-3.1 5.6-.6 1.5 1.5 2.1 3.4 2.2 4.6z"/><path fill="black" fill-opacity=".55" d="M14.1 10.8c3.1-.2 6.7-2.1 7-4.6.3-2.6-3.1-3.1-5.6-.6-1.5 1.5-2.1 3.4-2.2 4.6z"/><circle fill="black" cx="12" cy="6.3" r="2.5"/><path fill="black" fill-rule="evenodd" d="M12 8.9c2.8 0 4.9 2.6 4.9 5.9s-2.1 6.4-4.9 6.4-4.9-3.1-4.9-6.4 2.1-5.9 4.9-5.9zM8.4 12.5h7.2v1.6H8.4zM8.6 15.8h6.8v1.6H8.6z"/></svg>';
		return 'data:image/svg+xml;base64,' . base64_encode( $svg ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- WordPress admin menu icons are passed as base64 SVG data URIs.
	}

	/**
	 * Echo brand markup.
	 *
	 * @param string $markup From badge() or mark().
	 */
	public static function render( $markup ) {
		echo wp_kses( $markup, self::allowed() );
	}

	/**
	 * Allowed tags and attributes for brand markup.
	 *
	 * @return array
	 */
	public static function allowed() {
		$allowed                           = Icons::allowed();
		$allowed['path']['fill']           = true;
		$allowed['path']['stroke']         = true;
		$allowed['path']['stroke-opacity'] = true;
		$allowed['path']['stroke-width']   = true;
		$allowed['g']                      = array(
			'transform'       => true,
			'fill'            => true,
			'stroke'          => true,
			'stroke-width'    => true,
			'stroke-linecap'  => true,
			'stroke-linejoin' => true,
		);
		return $allowed;
	}

	/**
	 * Accessibility attributes.
	 *
	 * @param string $label Label.
	 * @return string
	 */
	private static function a11y( $label ) {
		return '' !== $label ? 'role="img" aria-label="' . esc_attr( $label ) . '"' : 'aria-hidden="true" focusable="false"';
	}
}
