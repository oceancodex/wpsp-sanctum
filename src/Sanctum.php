<?php

namespace WPSPCORE\Sanctum;

use WPSPCORE\Base\BaseInstances;
use WPSPCORE\Sanctum\Guards\TokenGuard;
use WPSPCORE\Sanctum\Guards\SessionGuard;

class Sanctum extends BaseInstances {

	private static $instance;
	private        $tokenGuard;
	private        $sessionGuard;
	private        $currentGuard      = null;
	private        $authenticatedUser = null;

	public function afterInstanceConstruct(): void {
		$useEloquent        = class_exists('\WPSPCORE\Database\Eloquent');
		$this->tokenGuard   = new TokenGuard($useEloquent);
		$this->sessionGuard = new SessionGuard();
	}

	/**
	 * Authenticate request
	 * Returns authenticated user or null
	 */
	public function authenticate() {
		// Try token first
		$token = $this->getTokenFromRequest();
		if ($token) {
			$this->currentGuard      = 'token';
			$this->authenticatedUser = $this->tokenGuard->authenticate($token);
			return $this->authenticatedUser;
		}

		// Try session
		$this->currentGuard      = 'session';
		$this->authenticatedUser = $this->sessionGuard->authenticate();
		return $this->authenticatedUser;
	}

	/**
	 * Check if authenticated
	 */
	public function check(): bool {
		if ($this->authenticatedUser === null) {
			$this->authenticate();
		}
		return $this->authenticatedUser !== null;
	}

	/**
	 * Get authenticated user
	 */
	public function user() {
		if ($this->authenticatedUser === null) {
			$this->authenticate();
		}
		return $this->authenticatedUser;
	}

	/**
	 * Check current guard
	 */
	public function usingTokenGuard(): bool {
		return $this->currentGuard === 'token';
	}

	public function usingSessionGuard(): bool {
		return $this->currentGuard === 'session';
	}

	/**
	 * Get token from request
	 */
	private function getTokenFromRequest(): ?string {
		$header = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
		if (preg_match('/Bearer\s+(.+)/i', $header, $matches)) {
			return trim($matches[1]);
		}
		return null;
	}

	/**
	 * Get current token guard
	 */
	public function getTokenGuard(): TokenGuard {
		return $this->tokenGuard;
	}

	/**
	 * Get current session guard
	 */
	public function getSessionGuard(): SessionGuard {
		return $this->sessionGuard;
	}

}