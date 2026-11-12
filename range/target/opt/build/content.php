<?php
// Build-time content for larkspurcycles.com. Run with `wp eval-file`.

$mreyes = get_user_by( 'login', 'mreyes' )->ID;
$lucia  = get_user_by( 'login', 'lucia' )->ID;

function lk_page( $title, $slug, $body, $author ) {
	return wp_insert_post( array(
		'post_type'    => 'page',
		'post_status'  => 'publish',
		'post_title'   => $title,
		'post_name'    => $slug,
		'post_content' => $body,
		'post_author'  => $author,
	) );
}

function lk_post( $title, $date, $body, $author, $cat ) {
	$cat_id = term_exists( $cat, 'category' );
	if ( ! $cat_id ) {
		$cat_id = wp_insert_term( $cat, 'category' );
	}
	return wp_insert_post( array(
		'post_status'   => 'publish',
		'post_title'    => $title,
		'post_content'  => $body,
		'post_author'   => $author,
		'post_date'     => $date,
		'post_category' => array( (int) ( is_array( $cat_id ) ? $cat_id['term_id'] : $cat_id ) ),
	) );
}

function p( ...$paras ) {
	return implode( "\n\n", array_map( fn( $t ) => "<!-- wp:paragraph -->\n<p>$t</p>\n<!-- /wp:paragraph -->", $paras ) );
}

wp_delete_post( 1, true ); // "Hello world!"
wp_delete_post( 2, true ); // "Sample Page"

$home = lk_page( 'Welcome to Larkspur Cycles', 'home', p(
	'Larkspur Cycles is a small repair shop and rental counter at the bottom of the Lookout Trail. We fix road, gravel and mountain bikes, rent hardtails by the day, and lead a free shop ride every Saturday at 8 a.m.',
	'Open Tuesday to Sunday, 9 to 6. Walk-ins are welcome for flats and quick adjustments; book a slot for anything that needs a stand for more than half an hour.'
), $mreyes );
lk_page( 'Repairs & Service', 'repairs', p(
	'Basic tune-up: $85. Brakes and gears adjusted, wheels trued, bolts checked. Most bikes are ready in two days.',
	'Full overhaul: $240. Drivetrain cleaned in the ultrasonic tank, bearings serviced, new cables and housing.',
	'Suspension service, wheel builds and hydraulic brake bleeds are quoted when we see the bike.'
), $mreyes );
lk_page( 'Rentals', 'rentals', p(
	'Hardtail mountain bikes: $45 per day, helmet included. Gravel bikes: $55 per day.',
	'Bring a photo ID and a card for the deposit. We open at 9 and want bikes back by 6.'
), $lucia );
lk_page( 'About', 'about', p(
	'Maria Reyes opened Larkspur in 2016 in the old feed store on Depot Street. Lucia joined in 2019 and runs the counter, the rentals and this website.',
	'We are three mechanics, two shop dogs, and one very old Park Tool stand.'
), $mreyes );
lk_page( 'Contact', 'contact', p(
	'112 Depot Street, Marshall NC. Phone (828) 555-0148.',
	'Email shop@larkspurcycles.com. We answer within a day, faster if it is raining.'
), $lucia );

$posts = array(
	array( 'Saturday shop ride: new route along the French Broad', '2026-08-30 08:12:00', p(
		'Starting this Saturday, the shop ride takes the river road north for 22 miles and comes back over Walnut Gap. Expect about 1,900 feet of climbing and one coffee stop.',
		'No-drop pace for the first hour. Lights are a good idea until the end of October.'
	), $lucia, 'Rides' ),
	array( 'Why your tubeless tire keeps going flat', '2026-09-08 14:40:00', p(
		'Most slow leaks we see come from sealant that dried out months ago. Shake the wheel: if nothing sloshes, it is time.',
		'Top up every two to three months in summer. Bring it in and we will reseat and refill it while you wait.'
	), $mreyes, 'Workshop' ),
	array( 'Fall rental hours', '2026-09-21 10:05:00', p(
		'From October 1 rentals go out from 9 to 5. Reservations made online before the change keep their times.'
	), $lucia, 'News' ),
	array( 'Ride report: Max Patch in the fog', '2026-10-04 19:22:00', p(
		'Eleven riders, zero views, and the best grilled cheese in Madison County. Thanks to everyone who came out and to Ben for the spare derailleur hanger.',
		'Send us your photos with the Share Your Ride form and we will add the best ones to the gallery.'
	), $lucia, 'Rides' ),
	array( 'Brake pads for wet weather', '2026-10-15 09:30:00', p(
		'Sintered pads last longer in grit and rain; organic pads are quieter and bite harder when cold. For most of our customers in the fall we suggest sintered in the rear and organic in the front.'
	), $mreyes, 'Workshop' ),
	array( 'Holiday gift cards are here', '2026-10-24 12:00:00', p(
		'Gift cards for tune-ups and rentals are on sale at the counter. Any amount over $25.'
	), $lucia, 'News' ),
);
foreach ( $posts as $post ) {
	lk_post( ...$post );
}

// "Share your ride": customers send a short story and a photo. The photo is the featured image of a pending post.
// This uses the Forminator post-data field, which carries CVE-2023-4596 in 1.24.6.
$form_id = Forminator_API::add_form(
	'Share your ride',
	array(
		array( 'wrapper_id' => 'wrapper-1729000000001-1001', 'fields' => array(
			array( 'element_id' => 'name-1', 'type' => 'name', 'cols' => '12', 'field_label' => 'Your name',
				'placeholder' => 'e.g. Sam Rivera', 'required' => 'true' ),
		) ),
		array( 'wrapper_id' => 'wrapper-1729000000002-1002', 'fields' => array(
			array( 'element_id' => 'email-1', 'type' => 'email', 'cols' => '12', 'field_label' => 'Email',
				'placeholder' => 'you@example.com', 'required' => 'true', 'validation' => true ),
		) ),
		array( 'wrapper_id' => 'wrapper-1729000000003-1003', 'fields' => array(
			array(
				'element_id'         => 'postdata-1',
				'type'               => 'postdata',
				'cols'               => '12',
				'data_status'        => 'pending',
				'post_title_label'   => 'Ride name',
				'post_content_label' => 'Tell us about it',
				'post_excerpt_label' => 'Post Excerpt',
				'post_image_label'   => 'Photo',
				'category_label'     => 'Category',
				'post_tag_label'     => 'Tags',
				'select_author'      => $lucia,
				'category_multiple'  => '0',
				'post_tag_multiple'  => '0',
				'post_type'          => 'post',
				'post_title'         => true,
				'post_content'       => true,
				'post_image'         => true,
				'options'            => array( array( 'label' => '', 'value' => '' ) ),
			),
		) ),
	),
	array(
		'formName'             => 'Share your ride',
		'form-type'            => 'default',
		'submission-behaviour' => 'behaviour-thankyou',
		'thankyou-message'     => 'Thanks! We will look at your ride and post it soon.',
		'submitData'           => array( 'custom-submit-text' => 'Send my ride' ),
		'enable-ajax'          => 'true',
		'validation-inline'    => true,
		'fields-style'         => 'open',
		'form-expire'          => 'no_expire',
		'store_submissions'    => '1',
	)
);
if ( is_wp_error( $form_id ) ) {
	WP_CLI::error( $form_id->get_error_message() );
}

lk_page( 'Share Your Ride', 'share-your-ride', p(
	'Rode somewhere good? Tell us where you went and send a photo. We post our favorites every week.'
) . "\n\n<!-- wp:shortcode -->\n[forminator_form id=\"$form_id\"]\n<!-- /wp:shortcode -->", $lucia );

update_option( 'show_on_front', 'page' );
update_option( 'page_on_front', $home );
update_option( 'larkspur_share_form', $form_id );
// The real payment key is planted per episode at boot (control/lib/web01-boot.sh and rangectl).
update_option( 'larkspur_payments', array( 'provider' => 'stripe', 'secret_key' => 'sk_live_PLACEHOLDER' ) );
