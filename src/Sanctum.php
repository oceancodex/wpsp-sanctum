<?php

namespace WPSPCORE\Sanctum;

use WPSPCORE\Base\BaseInstances;
use WPSPCORE\Sanctum\Guards\TokensGuard;
use WPSPCORE\Sanctum\Guards\SessionsGuard;

class Sanctum extends BaseInstances {

	private $tokenGuard;
	private $sessionGuard;
	private $currentGuard = null;
	private $authUser     = null;

	/*
	 *
	 */

	public function afterInstanceConstruct() {
		$this->tokenGuard   = new TokensGuard(
			$this->mainPath,
			$this->rootNamespace,
			$this->prefixEnv,
			[
				'provider'     => $this->extraParams['provider'],
				'session_key'  => $this->extraParams['session_key'],
				'guard_name'   => $this->extraParams['guard_name'],
				'guard_config' => $this->extraParams['guard_config'],
			]);
		$this->sessionGuard = new SessionsGuard(
			$this->mainPath,
			$this->rootNamespace,
			$this->prefixEnv,
			[
				'provider'     => $this->extraParams['provider'],
				'session_key'  => $this->extraParams['session_key'],
				'guard_name'   => $this->extraParams['guard_name'],
				'guard_config' => $this->extraParams['guard_config'],
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

	public function check() {
		if ($this->authUser === null) {
			$this->attempt();
		}
		return $this->authUser !== null;
	}

	/*
	 *
	 */

	public function attempt($credentials = []) {
		// Try token first.
		$plainToken = $this->funcs->_getBearerToken();
		if ($plainToken) {
			$this->currentGuard = 'token';
			$this->tokenGuard   = $this->tokenGuard->attempt(['plain_token' => $plainToken]);
			$this->authUser     = $this->tokenGuard ? $this->tokenGuard->user() : null;
			return $this->tokenGuard;
		}

		// Try session.
		if (empty($credentials)) {
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

	public function usingTokenGuard() {
		return $this->currentGuard === 'token';
	}

	public function usingSessionGuard() {
		return $this->currentGuard === 'session';
	}

	/**
	 * @return TokensGuard
	 */
	public function getTokenGuard() {
		return $this->tokenGuard;
	}

	/**
	 * @return SessionsGuard
	 */
	public function getSessionGuard() {
		return $this->sessionGuard;
	}

}