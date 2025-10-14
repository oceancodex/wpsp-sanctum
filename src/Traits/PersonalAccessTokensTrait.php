<?php

namespace WPSPCORE\Sanctum\Traits;

use Carbon\Carbon;

trait PersonalAccessTokensTrait {

	/**
	 * @return \Illuminate\Database\Eloquent\Relations\MorphTo
	 */
	public function tokenable() {
		return $this->morphTo('tokenable');
	}

	/*
	 *
	 */

	public function can($ability) {
		// Nếu expires_at là string, ép về Carbon
		$expiresAt = $this->expires_at instanceof \DateTimeInterface
			? $this->expires_at
			: Carbon::parse($this->expires_at);

		// Kiểm tra token còn hạn
		if ($expiresAt->lessThan(Carbon::now())) {
			return false;
		}

		// Kiểm tra quyền (abilities)
		$abilities = $this->abilities ?? [];

		return in_array('*', $abilities, true) || in_array($ability, $abilities, true);
	}

	public function cant($ability) {
		return !$this->can($ability);
	}

}