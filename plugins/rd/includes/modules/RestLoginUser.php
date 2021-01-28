<?php
/**
 * Create custom user
 *
 * @package rd
 */

namespace RD\modules;

/**
 * @
 */
class RestLoginUser {

	/**
	 * @
	 */
	public function __construct() {
		add_action( 'init', array( $this, 'create_login_rest_route' ) );
	}

	/**
	 * @
	 */
	public function create_login_rest_route() {
		register_rest_route(
			'rdlogin/v1',
			'/login',
			array(
				'methods'  => 'POST',
				'callback' => array( $this, 'login_rest_callback' ),
			)
		);
	}

	/**
	 * If a request is made to the custom login endpoint with a valid token, log in with provided credentials
	 */
	public function login_rest_callback( \WP_REST_Request $data ) {
		$login_info = json_decode( $data->get_body(), true );

		$username = $login_info['username'];
		$password = $login_info['password'];

		$creds = array(
			'user_login'    => $username,
			'user_password' => $password,
			'remember'      => true,
		);

		$user = wp_signon( $creds, false );

		if ( is_wp_error( $user ) ) {
				echo esc_html( $user->get_error_message() );
				return new \WP_REST_Response( null, 404 );
		}

		return new \WP_REST_Response( null, 200 );
	}

	/**
	 * @
	 */
	public function login_user() {
		if ( ! empty( $_POST ) || ! isset( $_POST['login_user_nonce'] )
		|| ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['login_user_nonce'] ) ), 'login_user' ) ) {

			if ( isset( $_POST['login_username'] ) && isset( $_POST['login_password'] ) && isset( $_POST['permalink'] ) ) {
				$username  = sanitize_text_field( wp_unslash( $_POST['login_username'] ) );
				$password  = sanitize_text_field( wp_unslash( $_POST['login_password'] ) );
				$permalink = sanitize_text_field( wp_unslash( $_POST['permalink'] ) );

				$creds = array(
					'user_login'    => $username,
					'user_password' => $password,
					'remember'      => true,
				);

				$user = wp_signon( $creds, false );

				if ( is_wp_error( $user ) ) {
						echo esc_html( $user->get_error_message() );
				}

				wp_safe_redirect( $permalink );
			}
		}
	}
}
