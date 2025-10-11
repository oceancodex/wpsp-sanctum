<?php
namespace WPSPCORE\Sanctum\Exceptions;

class MissingAbilityException extends \Exception {

	protected $abilities;

	public function __construct($abilities = [], $message = "", $code = 403) {
		parent::__construct($message ?: 'This action is unauthorized.', $code);
		$this->abilities = $abilities;
	}

	public function getAbilities() {
		return $this->abilities;
	}
}