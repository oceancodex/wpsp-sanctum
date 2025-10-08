<?php

namespace WPSPCORE\Sanctum\Guards;

use WPSPCORE\Auth\Base\BaseGuard;
use WPSPCORE\Auth\Models\DBAuthUser;

class SessionsGuard extends BaseGuard {

	private ?DBAuthUser $DBAuthUser = null;

	public function user() {
		$id = $this->id();
		if (!$id) return null;

		$this->rawUser = $this->provider->retrieveById($id);
		if (!$this->rawUser) return null;

		if ($this->rawUser instanceof \stdClass) {
			if (!($this->DBAuthUser instanceof DBAuthUser) || $this->DBAuthUser->rawUser !== $this->rawUser) {
				$this->DBAuthUser = new DBAuthUser(
					$this->funcs->_getMainPath(),
					$this->funcs->_getRootNamespace(),
					$this->funcs->_getPrefixEnv(),
					[
						'guard_name' => $this->guardName,
						'raw_user'   => $this->rawUser,
					]
				);
			}

			return $this->DBAuthUser;
		}
		else {
			// Add guard name.
			$this->rawUser->setAttribute('guard_name', $this->guardName);
//			$this->rawUser->setAttribute('access_token', '');
		}

		return $this->rawUser;
	}

}