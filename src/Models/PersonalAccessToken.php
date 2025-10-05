<?php

namespace WPSPCORE\Sanctum\Models;

class PersonalAccessToken {

	public $id;
	public $tokenable_type;
	public $tokenable_id;
	public $name;
	public $token;
	public $abilities;
	public $last_used_at;
	public $expires_at;
	public $created_at;
	public $updated_at;

	public function __construct(array $attributes = []) {
		foreach ($attributes as $key => $value) {
			if (property_exists($this, $key)) {
				$this->$key = $value;
			}
		}
	}

	public function can($ability) {
		$abilities = json_decode($this->abilities, true);

		if (in_array('*', $abilities)) {
			return true;
		}

		return in_array($ability, $abilities);
	}

	public function cant($ability) {
		return !$this->can($ability);
	}

	public function isExpired() {
		if ($this->expires_at === null) {
			return false;
		}

		return strtotime($this->expires_at) < time();
	}

	public function user() {
		if ($this->tokenable_type === 'WP_User') {
			return get_user_by('id', $this->tokenable_id);
		}

		return null;
	}

	public function toArray() {
		return [
			'id'             => $this->id,
			'tokenable_type' => $this->tokenable_type,
			'tokenable_id'   => $this->tokenable_id,
			'name'           => $this->name,
			'abilities'      => json_decode($this->abilities, true),
			'last_used_at'   => $this->last_used_at,
			'expires_at'     => $this->expires_at,
			'created_at'     => $this->created_at,
			'updated_at'     => $this->updated_at,
		];
	}

}