<?php

namespace WPSPCORE\Sanctum\Guards;

use WPSPCORE\Sanctum\Database\TokenDatabase;
use WPSPCORE\Sanctum\Sanctum;

class TokenGuard {

	private $user = null;

	/**
	 * Authenticate user via WordPress session
	 */
	public function authenticate($user_id) {
		// Lấy token từ header
		$token_string = Sanctum::getTokenFromRequest();
		// ↑ Returns: "abc123def456..." (plain text từ client)

		if (!$token_string) {
			return $user_id;
		}

		// Tìm token trong database
		$token = $this->database->findToken($token_string);
		// ↑ Hàm này sẽ:
		//   1. Hash token: SHA256("abc123def456...") = "7f3d2e1a..."
		//   2. Query DB: WHERE token = "7f3d2e1a..."
		//   3. Return PersonalAccessToken object hoặc null

		if (!$token || $token->isExpired()) {
			return $user_id;
		}

		// Token hợp lệ
		$this->token = $token;
		$this->user = $token->user(); // Get WP_User từ tokenable_id

		// Update last used
		$this->database->updateLastUsed($token->id);

		return $this->user->ID;
	}

	/**
	 * Check if request is from same origin (SPA)
	 */
	public function isFromSPA() {
		$referer = $_SERVER['HTTP_REFERER'] ?? '';
		$origin  = $_SERVER['HTTP_ORIGIN'] ?? '';

		if (empty($referer) && empty($origin)) {
			return false;
		}

		$site_url = get_site_url();

		// Check if referer or origin matches site URL
		return (
			strpos($referer, $site_url) === 0 ||
			strpos($origin, $site_url) === 0
		);
	}

	/**
	 * Authenticate for REST API with session
	 */
	public function restAuthenticate($result) {
		// If already authenticated or has error, return
		if ($result !== null) {
			return $result;
		}

		// Check if this is a session-based request from SPA
		if (!$this->isFromSPA()) {
			return $result;
		}

		// Check if user is logged in via WordPress session
		if (is_user_logged_in()) {
			$this->user = wp_get_current_user();

			// Verify CSRF token for state-changing methods
			if ($this->shouldVerifyCSRF()) {
				if (!$this->verifyCSRFToken()) {
					return new \WP_Error(
						'sanctum_csrf_token_mismatch',
						__('CSRF token mismatch.', 'wpspcore-sanctum'),
						['status' => 419]
					);
				}
			}

			return true;
		}

		return $result;
	}

	/**
	 * Check if CSRF verification is needed
	 */
	protected function shouldVerifyCSRF() {
		$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

		// Only verify CSRF for state-changing methods
		return in_array($method, ['POST', 'PUT', 'PATCH', 'DELETE']);
	}

	/**
	 * Verify CSRF token
	 */
	protected function verifyCSRFToken() {
		// Get token from header
		$token = $this->getCSRFTokenFromRequest();

		if (empty($token)) {
			return false;
		}

		// Verify WordPress nonce
		return wp_verify_nonce($token, 'sanctum_csrf_token');
	}

	/**
	 * Get CSRF token from request
	 */
	protected function getCSRFTokenFromRequest() {
		// Check X-XSRF-TOKEN header (Laravel Sanctum compatible)
		if (isset($_SERVER['HTTP_X_XSRF_TOKEN'])) {
			return $_SERVER['HTTP_X_XSRF_TOKEN'];
		}

		// Check X-CSRF-TOKEN header
		if (isset($_SERVER['HTTP_X_CSRF_TOKEN'])) {
			return $_SERVER['HTTP_X_CSRF_TOKEN'];
		}

		// Check from cookie
		if (isset($_COOKIE['XSRF-TOKEN'])) {
			return $_COOKIE['XSRF-TOKEN'];
		}

		return null;
	}

	/**
	 * Generate CSRF token
	 */
	public function generateCSRFToken() {
		return wp_create_nonce('sanctum_csrf_token');
	}

	/**
	 * Set CSRF token cookie
	 */
	public function setCSRFCookie() {
		$token = $this->generateCSRFToken();

		setcookie(
			'XSRF-TOKEN',
			$token,
			[
				'expires'  => time() + (60 * 60 * 2), // 2 hours
				'path'     => '/',
				'domain'   => $this->getCookieDomain(),
				'secure'   => is_ssl(),
				'httponly' => false, // Must be false so JavaScript can read it
				'samesite' => 'Lax',
			]
		);

		return $token;
	}

	/**
	 * Get cookie domain
	 */
	protected function getCookieDomain() {
		$parsed = parse_url(get_site_url());
		return $parsed['host'] ?? '';
	}

	/**
	 * Get current user
	 */
	public function user() {
		return $this->user;
	}

	/**
	 * Check if authenticated
	 */
	public function check() {
		return $this->user !== null;
	}

	/**
	 * Check if guest
	 */
	public function guest() {
		return !$this->check();
	}

}