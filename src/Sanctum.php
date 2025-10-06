<?php

namespace WPSPCORE\Sanctum;

use WPSPCORE\Base\BaseInstances;
use WPSPCORE\Sanctum\Guards\TokenGuard;
use WPSPCORE\Sanctum\Guards\SessionGuard;

class Sanctum extends BaseInstances {

	private TokenGuard   $tokenGuard;
	private SessionGuard $sessionGuard;
	private              $currentGuard      = null;
	private              $authenticatedUser = null;

	/*
	 *
	 */

	public function afterInstanceConstruct(): void {
		$this->tokenGuard   = new TokenGuard();
		$this->sessionGuard = new SessionGuard();
	}

	/*
	 *
	 */

	private function getTokenFromRequest(): ?string {
		$header = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
		if (preg_match('/Bearer\s+(.+)/i', $header, $matches)) {
			return trim($matches[1]);
		}
		return null;
	}

	/*
	 *
	 */

	public function user() {
		if ($this->authenticatedUser === null) {
			$this->authenticate();
		}
		return $this->authenticatedUser;
	}

	public function check(): bool {
		if ($this->authenticatedUser === null) {
			$this->authenticate();
		}
		return $this->authenticatedUser !== null;
	}

	/*
	 *
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

	/*
	 *
	 */

	public function usingTokenGuard(): bool {
		return $this->currentGuard === 'token';
	}

	public function usingSessionGuard(): bool {
		return $this->currentGuard === 'session';
	}

	public function getTokenGuard(): TokenGuard {
		return $this->tokenGuard;
	}

	public function getSessionGuard(): SessionGuard {
		return $this->sessionGuard;
	}

}