"""The shop's own small WordPress plugin, larkspur-site, in its release N. Pure text, no range material.

The image build writes release 0 (range/target/opt/build/setup-target.sh). During an episode the CI persona pushes
release N and Maria (the developer persona) changes a file by hand. Both use these functions, so the driver knows
the exact content, and the grader can tell these benign file changes from an intruder's (grade.py, benign files).

    python3 sitegen.py DIR N     write release N into DIR
"""
import hashlib
import pathlib
import sys

DIR = "/var/www/larkspur/wp-content/plugins/larkspur-site"

BIKES = [("Hardtail (Trek Marlin 7)", 45), ("Gravel (Salsa Journeyman)", 55), ("Kids 24in", 25),
         ("E-bike (Specialized Turbo Vado)", 85), ("Tandem", 70), ("Fat bike", 50)]
NOTES = ["Helmet included.", "Bring a photo ID and a card for the deposit.", "Back by 6, please.",
         "Half-day rates after 2 p.m.", "Ask about the Saturday shop ride.", "Lights on request."]


def version(n):
    return f"1.4.{n}"


def main_php(n):
    return f"""<?php
/**
 * Plugin Name: Larkspur Site
 * Description: Small site features for larkspurcycles.com: rental price list, shop hours, footer note.
 * Version: {version(n)}
 * Author: Larkspur Cycles
 */

defined( 'ABSPATH' ) || exit;

define( 'LARKSPUR_SITE_VERSION', '{version(n)}' );

require_once __DIR__ . '/inc/rentals.php';
require_once __DIR__ . '/inc/hours.php';

add_action( 'wp_enqueue_scripts', function () {{
	wp_enqueue_style( 'larkspur-site', plugins_url( 'assets/site.css', __FILE__ ), array(), LARKSPUR_SITE_VERSION );
	wp_enqueue_script( 'larkspur-site', plugins_url( 'assets/site.js', __FILE__ ), array(), LARKSPUR_SITE_VERSION, true );
}} );
"""


def rentals_php(n, tweak=0):
    rows = []
    for i, (bike, price) in enumerate(BIKES[: 3 + (n + tweak) % 4]):
        rows.append(f"\t\tarray( '{bike}', {price + ((n + i + tweak) % 3) * 5} ),")
    note = NOTES[(n + tweak) % len(NOTES)]
    return f"""<?php
// Rental price list: [larkspur_rentals]
defined( 'ABSPATH' ) || exit;

function larkspur_rental_prices() {{
	return array(
{chr(10).join(rows)}
	);
}}

add_shortcode( 'larkspur_rentals', function () {{
	$out = '<table class="larkspur-rentals"><tr><th>Bike</th><th>Per day</th></tr>';
	foreach ( larkspur_rental_prices() as $row ) {{
		$out .= '<tr><td>' . esc_html( $row[0] ) . '</td><td>$' . (int) $row[1] . '</td></tr>';
	}}
	return $out . '</table><p class="larkspur-note">{note}</p>';
}} );
"""


def hours_php(n):
    close = 6 if n % 5 else 7
    return f"""<?php
// Shop hours: [larkspur_hours]
defined( 'ABSPATH' ) || exit;

add_shortcode( 'larkspur_hours', function () {{
	return '<p class="larkspur-hours">Tuesday to Sunday, 9 to {close}. Closed Mondays.</p>';
}} );
"""


def site_css(n, tweak=0):
    hue = (140 + 7 * n + 13 * tweak) % 360
    return f"""/* larkspur-site {version(n)} */
.larkspur-rentals {{ border-collapse: collapse; width: 100%; max-width: 32rem; }}
.larkspur-rentals th, .larkspur-rentals td {{ padding: .4rem .6rem; border-bottom: 1px solid #ddd; text-align: left; }}
.larkspur-note, .larkspur-hours {{ color: hsl({hue}, 30%, 30%); font-size: .95rem; }}
"""


def site_js(n):
    return f"""/* larkspur-site {version(n)} */
document.addEventListener('DOMContentLoaded', function () {{
  document.querySelectorAll('.larkspur-rentals tr').forEach(function (row, i) {{
    if (i % 2) row.style.background = '#f7f7f4';
  }});
}});
"""


def release(n):
    """{relative path: text} of release n."""
    return {"larkspur-site.php": main_php(n), "inc/rentals.php": rentals_php(n), "inc/hours.php": hours_php(n),
            "assets/site.css": site_css(n), "assets/site.js": site_js(n),
            "CHANGELOG.md": "".join(f"## {version(i)}\n- rentals and hours update\n\n" for i in range(n, -1, -1))}


def sha256(text):
    return hashlib.sha256(text.encode()).hexdigest()


if __name__ == "__main__":
    out = pathlib.Path(sys.argv[1])
    for rel, text in release(int(sys.argv[2])).items():
        (out / rel).parent.mkdir(parents=True, exist_ok=True)
        (out / rel).write_text(text)
