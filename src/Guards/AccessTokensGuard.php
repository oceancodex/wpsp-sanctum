<?php

namespace WPSPCORE\Sanctum\Guards;

use WPSPCORE\Auth\Base\BaseGuard;
use WPSPCORE\Sanctum\Database\DBPersonalAccessToken;

class AccessTokensGuard extends BaseGuard {

	private   $currentToken;
	private   $modelClass;
	protected $currentAccessToken;

	public function afterInstanceConstruct() {
		parent::afterInstanceConstruct();
		$this->modelClass = $this->funcs->_config('sanctum.model');
	}

	public function attempt($credentials = []) {
		$plainToken = $credentials['plain_token'] ?? '';

		if (!$plainToken) {
			return false;
		}

		$plainToken = explode('|', $plainToken);
		$tokenId    = $plainToken[0] ?? 0;
		$tokenRaw   = $plainToken[1] ?? '';

		if ($this->modelClass) {
			$hashedToken              = hash('sha256', $plainToken[1]);
			$this->currentAccessToken = $this->modelClass::where('token', $hashedToken)->where('id', $tokenId)->first();
		}
		else {
			// TODO: Chưa xử lý lấy user từ token nếu không có model class.
			$this->currentAccessToken = (new DBPersonalAccessToken)->findByToken($tokenRaw);
		}

		return $this;
	}

	public function user() {
		if (!$this->currentAccessToken) return null;
		// TODO: Chưa xử lý lấy user từ token nếu không có model class.
		return $this->currentAccessToken->tokenable()->first();
	}

}