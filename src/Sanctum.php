<?php

namespace WPSPCORE\Sanctum;

use WPSPCORE\Base\BaseInstances;
use WPSPCORE\Sanctum\Guards\AccessTokensGuard;
use WPSPCORE\Sanctum\Guards\SessionsGuard;

class Sanctum extends BaseInstances {

	private $tokenGuard;
	private $sessionGuard;
	private $currentGuard = null;
	private $authUser     = null;

	/*
	 *
	 */

	public function afterInstanceConstruct(): void {
		$this->tokenGuard   = new AccessTokensGuard(
			$this->mainPath,
			$this->rootNamespace,
			$this->prefixEnv,
			[
				'provider'     => $this->customProperties['provider'],
				'session_key'  => $this->customProperties['session_key'],
				'guard_name'   => $this->customProperties['guard_name'],
				'guard_config' => $this->customProperties['guard_config'],
			]);
		$this->sessionGuard = new SessionsGuard(
			$this->mainPath,
			$this->rootNamespace,
			$this->prefixEnv,
			[
				'provider'     => $this->customProperties['provider'],
				'session_key'  => $this->customProperties['session_key'],
				'guard_name'   => $this->customProperties['guard_name'],
				'guard_config' => $this->customProperties['guard_config'],
			]);
	}

	/*
	 *
	 */

	public function user() {
		if ($this->authUser === null) {
			$this->attempt();
		}
		return $this->authUser;
	}

	public function check(): bool {
		if ($this->authUser === null) {
			$this->attempt();
		}
		return $this->authUser !== null;
	}

	/*
	 *
	 */

	public function attempt(array $credentials = []) {
		$plainToken = $this->funcs->_getBearerToken();
		if ($plainToken) {
			$this->currentGuard = 'token';
			$this->tokenGuard   = $this->tokenGuard->attempt(['plain_token' => $plainToken]);
			$this->authUser     = $this->tokenGuard ? $this->tokenGuard->user() : null;
			return $this->tokenGuard;
		}

		// Try session
		if (!$credentials) {
			$credentials             = [];
			$credentials['login']    = $this->request->get('login');
			$credentials['password'] = $this->request->get('password');
		}
		$this->currentGuard = 'session';
		$this->sessionGuard = $this->sessionGuard->attempt($credentials);
		$this->authUser     = $this->sessionGuard ? $this->sessionGuard->user() : null;
		return $this->sessionGuard;
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

	public function getTokenGuard(): AccessTokensGuard {
		return $this->tokenGuard;
	}

	public function getSessionGuard(): SessionsGuard {
		return $this->sessionGuard;
	}

}