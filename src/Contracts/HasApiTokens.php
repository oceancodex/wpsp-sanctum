<?php

namespace WPSPCORE\Sanctum\Contracts;

interface HasApiTokens {
	public function createToken(string $name, array $abilities = ['*'], $expiresAt = null);
	public function tokens();
	public function currentAccessToken();
}