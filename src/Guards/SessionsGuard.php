<?php

namespace WPSPCORE\Sanctum\Guards;

use WPSPCORE\Auth\Base\BaseGuard;
use WPSPCORE\Auth\Models\DBAuthUserModel;

class SessionsGuard extends BaseGuard {

	public function attempt($credentials = []) {
		if (empty($credentials)) {
			$credentials             = [];
			$credentials['login']    = $this->request->get('login');
			$credentials['password'] = $this->request->get('password');
		}

		$user = $this->provider->retrieveByCredentials($credentials);

		if (!$user) return false;
		$this->authUser = $this->prepareUser($user, DBAuthUserModel::class);

		foreach ($this->provider->dbPasswordFields as $dbPasswordField) {
			foreach ($this->provider->formPasswordFields as $formPasswordField) {
				$given  = $credentials[$formPasswordField] ?? null;
				$hashed = $user->{$dbPasswordField} ?? null;
				if ($given !== null && $hashed && wp_check_password($given, $hashed)) {
					$id = null;
					foreach ($this->provider->dbIdFields as $dbIdField) {
						try {
							$id = $user->{$dbIdField} ?? null;
						}
						catch (\Exception $e) {
							continue;
						}
						if ($id) break;
					}
					if (!$id) return false;
					$_SESSION[$this->sessionKey] = $id;
					return $this;
				}
			}
		}

		return false;
	}

	/*
	 *
	 */

	public function id() {
		return !empty($_SESSION[$this->sessionKey]) ? $_SESSION[$this->sessionKey] : null;
	}

	public function user() {
		if (!$this->id()) return null;
		$user = $this->provider->retrieveById($this->id());
		if (!$user) return null;
		$this->authUser = $this->prepareUser($user, DBAuthUserModel::class);
		return $this->authUser;
	}

	public function check() {
		return $this->id() !== null;
	}

}