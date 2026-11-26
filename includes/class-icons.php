<?php
/**
 * Inline SVG icons (Lucide, ISC License) rendered from bundled geometry data.
 *
 * Icons are decorative (hidden from assistive technology) unless a label is given.
 *
 * @package BeeMonitor
 */

namespace BeeMonitor;

defined( 'ABSPATH' ) || exit;

/**
 * Icon renderer.
 */
final class Icons {

	/**
	 * Icon geometry keyed by Lucide name.
	 *
	 * @var array|null
	 */
	private static $data = null;

	/**
	 * Icon markup.
	 *
	 * @param string $name Lucide icon name.
	 * @param array  $args size (px), label (accessible name; empty = decorative), class.
	 * @return string Markup built only from escaped values; print it with wp_kses( ..., Icons::allowed() ).
	 */
	public static function svg( $name, array $args = array() ) {
		if ( null === self::$data ) {
			$data       = include BEE_MONITOR_DIR . 'includes/icons-data.php';
			self::$data = is_array( $data ) ? $data : array();
		}
		if ( ! isset( self::$data[ $name ] ) ) {
			return '';
		}
		$size  = isset( $args['size'] ) ? max( 8, min( 64, (int) $args['size'] ) ) : 16;
		$label = isset( $args['label'] ) ? (string) $args['label'] : '';
		$class = trim( 'bee-monitor-icon bee-monitor-icon-' . $name . ' ' . ( isset( $args['class'] ) ? (string) $args['class'] : '' ) );
		$a11y  = '' !== $label ? 'role="img" aria-label="' . esc_attr( $label ) . '"' : 'aria-hidden="true" focusable="false"';
		$out   = sprintf( '<svg class="%1$s" width="%2$d" height="%2$d" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" %3$s>', esc_attr( $class ), $size, $a11y );
		foreach ( self::$data[ $name ] as $shape ) {
			$out .= '<' . tag_escape( $shape[0] );
			foreach ( $shape[1] as $attr => $value ) {
				$out .= ' ' . sanitize_key( $attr ) . '="' . esc_attr( $value ) . '"';
			}
			$out .= '></' . tag_escape( $shape[0] ) . '>';
		}
		return $out . '</svg>';
	}

	/**
	 * Echo an icon.
	 *
	 * @param string $name Lucide icon name.
	 * @param array  $args See svg().
	 */
	public static function render( $name, array $args = array() ) {
		echo wp_kses( self::svg( $name, $args ), self::allowed() );
	}

	/**
	 * Tags and attributes allowed in icon markup (for wp_kses).
	 *
	 * @return array
	 */
	public static function allowed() {
		return array(
			'svg'     => array(
				'class'           => true,
				'width'           => true,
				'height'          => true,
				'viewbox'         => true,
				'fill'            => true,
				'stroke'          => true,
				'stroke-width'    => true,
				'stroke-linecap'  => true,
				'stroke-linejoin' => true,
				'role'            => true,
				'aria-label'      => true,
				'aria-hidden'     => true,
				'focusable'       => true,
			),
			'path'    => array( 'd' => true ),
			'circle'  => array(
				'cx' => true,
				'cy' => true,
				'r'  => true,
			),
			'rect'    => array(
				'x'      => true,
				'y'      => true,
				'width'  => true,
				'height' => true,
				'rx'     => true,
				'ry'     => true,
			),
			'line'    => array(
				'x1' => true,
				'y1' => true,
				'x2' => true,
				'y2' => true,
			),
			'ellipse' => array(
				'cx' => true,
				'cy' => true,
				'rx' => true,
				'ry' => true,
			),
		);
	}
}
