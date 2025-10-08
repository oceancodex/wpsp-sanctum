<?php

namespace WPSPCORE\Sanctum\Guards;

use WPSPCORE\Auth\Base\BaseGuard;
use WPSPCORE\Auth\Drivers\Database\DBAuthUser;
use WPSPCORE\Sanctum\Database\DBPersonalAccessToken;

class AccessTokensGuard extends BaseGuard {

	protected $currentAccessToken;

	private ?DBAuthUser $DBAuthUser = null;

	public function attempt($credentials = []) {
		$plainToken = $credentials['plain_token'] ?? $this->funcs->_getBearerToken();

		if (!$plainToken) {
			return false;
		}

		$plainTokenArr = explode('|', $plainToken);
		$tokenId    = $plainTokenArr[0] ?? 0;
		$tokenRaw   = $plainTokenArr[1] ?? '';

		$personalAccessTokenModel = $this->funcs->_config('sanctum.model_class');
		if (class_exists($personalAccessTokenModel) && !$this->provider->customProperties['table']) {
			$hashedToken = hash('sha256', $tokenRaw);
			$this->currentAccessToken = $personalAccessTokenModel::where('token', $hashedToken)->where('id', $tokenId)->first();
		}
		else {
			$this->currentAccessToken = (new DBPersonalAccessToken(
				$this->funcs->_getMainPath(),
				$this->funcs->_getRootNamespace(),
				$this->funcs->_getPrefixEnv(),
				[]
			))->findByToken($plainToken);
		}

		return $this;
	}

	public function user() {
		if (!$this->currentAccessToken) return null;
		if (!$this->currentAccessToken instanceof DBPersonalAccessToken) {
			return $this->currentAccessToken->user();
		}
		else {
			return $this->currentAccessToken->tokenable()->first();
		}
	}

}