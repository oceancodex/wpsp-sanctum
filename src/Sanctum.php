<?php

namespace WPSPCORE\Sanctum;

use WPSPCORE\Sanctum\Database\TokenDatabase;
use WPSPCORE\Sanctum\Guards\SanctumGuard;

class Sanctum {

	private static $instance     = null;
	private        $database;
	private        $tokenGuard;
	private        $sessionGuard;
	private        $currentGuard = null;

	private function __construct() {
		$this->database     = new TokenDatabase();
		$this->tokenGuard   = new SanctumGuard($this->database);
		$this->sessionGuard = new SessionGuard();
	}

	public static function getInstance() {
		if (self::$instance === null) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	public function init() {
		// Create database table on activation
		add_action('after_setup_theme', [$this, 'createTokenTable']);

		// Hook into WordPress authentication
		add_filter('determine_current_user', [$this, 'authenticate'], 10);

		// Add REST API authentication
		add_filter('rest_authentication_errors', [$this, 'restAuthenticate']);

		// Set CSRF cookie for session-based auth
		add_action('init', [$this, 'ensureCSRFCookie']);

		// Add CSRF token endpoint
		add_action('rest_api_init', [$this, 'registerCSRFRoute']);
	}

	public function createTokenTable() {
		$this->database->createTable();
	}

	/**
	 * Authenticate user - determines which guard to use
	 */
	public function authenticate($user_id) {
		// Try token authentication first
		$token = self::getTokenFromRequest();

		if ($token) {
			$this->currentGuard = 'token';
			return $this->tokenGuard->authenticate($user_id);
		}

		// Fall back to session authentication
		$this->currentGuard = 'session';
		return $this->sessionGuard->authenticate($user_id);
	}

	/**
	 * REST API authentication - supports both guards
	 */
	public function restAuthenticate($result) {
		// Try token authentication first
		$token = self::getTokenFromRequest();

		if ($token) {
			$this->currentGuard = 'token';
			return $this->tokenGuard->restAuthenticate($result);
		}

		// Try session authentication for SPA
		if ($this->sessionGuard->isFromSPA()) {
			$this->currentGuard = 'session';
			return $this->sessionGuard->restAuthenticate($result);
		}

		return $result;
	}

	/**
	 * Ensure CSRF cookie is set for session-based requests
	 */
	public function ensureCSRFCookie() {
		// Only set cookie for logged-in users from SPA
		if (is_user_logged_in() && $this->sessionGuard->isFromSPA()) {
			if (!isset($_COOKIE['XSRF-TOKEN'])) {
				$this->sessionGuard->setCSRFCookie();
			}
		}
	}

	/**
	 * Register CSRF token endpoint
	 */
	public function registerCSRFRoute() {
		register_rest_route('sanctum', '/csrf-cookie', [
			'methods'             => 'GET',
			'callback'            => [$this, 'getCSRFCookie'],
			'permission_callback' => '__return_true',
		]);
	}

	/**
	 * Get CSRF cookie endpoint
	 */
	public function getCSRFCookie() {
		$token = $this->sessionGuard->setCSRFCookie();

		return [
			'success' => true,
			'message' => 'CSRF cookie set',
			'token'   => $token,
		];
	}

	/**
	 * Get the active guard
	 */
	public function getGuard() {
		if ($this->currentGuard === 'token') {
			return $this->tokenGuard;
		}

		if ($this->currentGuard === 'session') {
			return $this->sessionGuard;
		}

		// Default to token guard
		return $this->tokenGuard;
	}

	/**
	 * Get token guard specifically
	 */
	public function getTokenGuard() {
		return $this->tokenGuard;
	}

	/**
	 * Get session guard specifically
	 */
	public function getSessionGuard() {
		return $this->sessionGuard;
	}

	/**
	 * Get current authenticated user
	 */
	public function currentUser() {
		return $this->getGuard()->user();
	}

	/**
	 * Check if authenticated
	 */
	public function check() {
		return $this->getGuard()->check();
	}

	/**
	 * Check which guard is currently active
	 */
	public function usingTokenGuard() {
		return $this->currentGuard === 'token';
	}

	/**
	 * Check which guard is currently active
	 */
	public function usingSessionGuard() {
		return $this->currentGuard === 'session';
	}

	/**
	 * Get the token from the request
	 */
	public static function getTokenFromRequest() {
		$header = $_SERVER['HTTP_AUTHORIZATION'] ?? '';

		if (empty($header)) {
			return null;
		}

		if (strpos($header, 'Bearer ') === 0) {
			return substr($header, 7);
		}

		return null;
	}

}