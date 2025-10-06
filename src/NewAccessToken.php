<?php

namespace WPSPCORE\Sanctum;

use WPSP\app\Models\PersonalAccessTokenModel;

class NewAccessToken {

	public $accessToken;

	public $plainTextToken;

	public function __construct(PersonalAccessTokenModel $accessToken, string $plainTextToken) {
		$this->accessToken    = $accessToken;
		$this->plainTextToken = $plainTextToken;
	}

	public function toArray() {
		return [
			'accessToken'    => $this->accessToken,
			'plainTextToken' => $this->plainTextToken,
		];
	}

	public function toJson($options = 0) {
		return json_encode($this->toArray(), $options);
	}

}