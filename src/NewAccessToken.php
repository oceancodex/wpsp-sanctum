<?php

namespace WPSPCORE\Sanctum;

use WPSP\app\Models\PersonalAccessTokenModel;

class NewAccessToken {

	public $plainToken;
	public $accessToken;

	public function __construct($accessToken, $plainToken) {
		$this->accessToken = $accessToken;
		$this->plainToken  = $plainToken;
	}

	public function toArray() {
		return [
			'plain_token'  => $this->plainToken,
			'access_token' => $this->accessToken,
		];
	}

	public function toJson($options = 0) {
		return json_encode($this->toArray(), $options);
	}

}