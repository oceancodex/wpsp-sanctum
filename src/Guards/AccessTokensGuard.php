<?php

namespace WPSPCORE\Sanctum\Guards;

use WPSPCORE\Auth\Base\BaseGuard;
use WPSPCORE\Auth\Models\DBAuthUserModel;
use WPSPCORE\Sanctum\Database\DBPersonalAccessTokens;
use WPSPCORE\Sanctum\Database\DBPersonalAccessTokensModel;

class AccessTokensGuard extends BaseGuard {

	public $accessToken;

	/*
	 *
	 */

	public function attempt($credentials = []) {
		$plainToken = $credentials['plain_token'] ?? $this->funcs->_getBearerToken();

		if (!$plainToken) {
			return false;
		}

		$plainTokenArr = explode('|', $plainToken);
		$tokenId       = $plainTokenArr[0] ?? 0;
		$tokenRaw      = $plainTokenArr[1] ?? '';

		$personalAccessTokenModel = $this->funcs->_config('sanctum.model_class');
		if (class_exists($personalAccessTokenModel) && !$this->provider->customProperties['table']) {
			$hashedToken       = hash('sha256', $tokenRaw);
			$this->accessToken = $personalAccessTokenModel::where('token', $hashedToken)->where('id', $tokenId)->first();
		}
		else {
			$model             = new DBPersonalAccessTokens(
				$this->funcs->_getMainPath(),
				$this->funcs->_getRootNamespace(),
				$this->funcs->_getPrefixEnv(),
				[
					'provider'     => $this->customProperties['provider'],
					'session_key'  => $this->customProperties['session_key'],
					'guard_name'   => $this->customProperties['guard_name'],
					'guard_config' => $this->customProperties['guard_config'],
				]
			);
			$this->accessToken = $model->findByToken($plainToken);
			$this->accessToken = new DBPersonalAccessTokensModel(
				$this->funcs->_getMainPath(),
				$this->funcs->_getRootNamespace(),
				$this->funcs->_getPrefixEnv(),
				[
					'access_token' => $this->accessToken,
					'provider'     => $this->customProperties['provider'],
					'session_key'  => $this->customProperties['session_key'],
					'guard_name'   => $this->customProperties['guard_name'],
					'guard_config' => $this->customProperties['guard_config'],
				]
			);
		}

		return $this;
	}

	public function user() {
		if (!$this->accessToken) return null;
		if ($this->accessToken instanceof DBPersonalAccessTokensModel) {
			$user = $this->accessToken->user();
			return new DBAuthUserModel(
				$this->funcs->_getMainPath(),
				$this->funcs->_getRootNamespace(),
				$this->funcs->_getPrefixEnv(),
				[
					'auth_user'    => $user,
					'access_token' => $this->accessToken,
					'provider'     => $this->customProperties['provider'],
					'session_key'  => $this->customProperties['session_key'],
					'guard_name'   => $this->customProperties['guard_name'],
					'guard_config' => $this->customProperties['guard_config'],
				]);
		}
		else {
			return $this->accessToken->tokenable()->first();
		}
	}

}