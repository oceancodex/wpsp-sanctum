<?php

namespace WPSPCORE\Sanctum\Guards;

use WPSPCORE\Auth\Base\BaseGuard;
use WPSPCORE\Auth\Models\DBAuthUserModel;
use WPSPCORE\Sanctum\Database\DBPersonalAccessTokens;
use WPSPCORE\Sanctum\Models\DBPersonalAccessTokensModel;

class TokensGuard extends BaseGuard {

	public $accessToken;

	/*
	 *
	 */

	/**
	 * Xác thực.
	 * @param $credentials
	 *
	 * @return false|static
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
			$DBPersonalAccessTokens = new DBPersonalAccessTokens(
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

			$accessToken = $DBPersonalAccessTokens->findByToken($plainToken);

			$this->accessToken = new DBPersonalAccessTokensModel(
				$this->funcs->_getMainPath(),
				$this->funcs->_getRootNamespace(),
				$this->funcs->_getPrefixEnv(),
				[
					'access_token' => $accessToken,
					'provider'     => $this->customProperties['provider'],
					'session_key'  => $this->customProperties['session_key'],
					'guard_name'   => $this->customProperties['guard_name'],
					'guard_config' => $this->customProperties['guard_config'],
				]
			);
		}

		return $this;
	}

	/*
	 *
	 */

	/**
	 * Lấy ID của token.
	 */
	public function id(): ?int {
		return $this->accessToken->id ?? $this->accessToken->ID ?? null;
	}

	/**
	 * Lấy thông tin người dùng từ token.
	 */
	public function user() {
		if (!$this->accessToken) return null;

		if ($this->accessToken instanceof DBPersonalAccessTokensModel) {
			return $this->prepareUser($this->accessToken->user(), DBAuthUserModel::class);
		}
		else {
			return $this->accessToken->tokenable()->first();
		}
	}

	/**
	 * Kiểm tra token có tồn tại hay không.
	 */
	public function check(): bool {
		// Cố gắng xác thực lại một lần nữa, nếu "check" được gọi độc lập.
		// Tức là dùng luôn auth('sanctum')->check() thay vì $auth = auth('sanctum')->attempt() > $auth->check().
		if (!$this->accessToken) {
			$this->attempt();
		}
		return $this->id() !== null;
	}

}