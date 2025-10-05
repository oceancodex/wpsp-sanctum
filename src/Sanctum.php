<?php

namespace WPSPCORE\Sanctum;

use WPSPCORE\Sanctum\Database\TokenDatabase;
use WPSPCORE\Sanctum\Guards\SanctumGuard;

class Sanctum {

	private static $instance = null;
	private        $database;
	private        $guard;

	private function __construct() {
		$this->database = new TokenDatabase();
		$this->guard    = new SanctumGuard($this->database);
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
		add_filter('determine_current_user', [$this->guard, 'authenticate'], 10);

		// Add REST API authentication
		add_filter('rest_authentication_errors', [$this->guard, 'restAuthenticate']);
	}

	public function createTokenTable() {
		$this->database->createTable();
	}

	public function getGuard() {
		return $this->guard;
	}

	public function currentUser() {
		return $this->guard->user();
	}

	public function check() {
		return $this->guard->check();
	}

	public function getGuard() {
		return $this->guard;
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