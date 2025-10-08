<?php
namespace WPSPCORE\Sanctum\Exceptions;

class MissingAbilityException extends \Exception {

	protected array $abilities;

	public function __construct(array $abilities = [], $message = "", $code = 403) {
		parent::__construct($message ?: 'This action is unauthorized.', $code);
		$this->abilities = $abilities;
	}

	public function getAbilities(): array {
		return $this->abilities;
	}
}