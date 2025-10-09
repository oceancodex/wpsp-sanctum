<?php

namespace WPSPCORE\Sanctum\Guards;

use WPSPCORE\Auth\Base\BaseGuard;
use WPSPCORE\Auth\Models\DBAuthUserModel;

class SessionsGuard extends BaseGuard {

	private ?DBAuthUserModel $DBAuthUser = null;

	public function user() {
		$id = $this->id();
		if (!$id) return null;

		$this->authUser = $this->provider->retrieveById($id);
		if (!$this->authUser) return null;

		if ($this->authUser instanceof \stdClass) {
			if (!($this->DBAuthUser instanceof DBAuthUserModel) || $this->DBAuthUser->authUser !== $this->authUser) {
				$this->DBAuthUser = new DBAuthUserModel(
					$this->funcs->_getMainPath(),
					$this->funcs->_getRootNamespace(),
					$this->funcs->_getPrefixEnv(),
					[
						'auth_user'    => $this->authUser,
						'provider'     => $this->provider,
						'session_key'  => $this->sessionKey,
						'guard_name'   => $this->guardName,
						'guard_config' => $this->guardConfig,
					]
				);
			}

			return $this->DBAuthUser;
		}
		else {
			// Add guard name.
			$this->authUser->setAttribute('guard_name', $this->guardName);
//			$this->authUser->setAttribute('access_token', '');
		}

		return $this->authUser;
	}

}