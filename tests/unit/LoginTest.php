<?php

use App\Oauth2;
use Codeception\Util\Stub;

class LoginTest extends \Codeception\Test\Unit
{
	const IBMID_ENDPOINT_BASE_URL = 'http://app.com';
	const IBMID_CLIENT_ID         = 'abcdefgh';
	const IBMID_CLIENT_SECRET     = '123456789';
	const STATE                   = 'abc123';

	/**
	 * @var Oauth2
	 */
	private $object;
	private $session;
	private $httpClient;
	private $jwtParser;

	/**
	 * @var \UnitTester
	 */
	protected $tester;

	protected function _before()
	{
		$this->session    = Stub::make('\App\Session');
		$this->httpClient = Stub::make('\GuzzleHttp\Client');
		$this->jwtParser  = Stub::make('\Lcobucci\JWT\Parser');

		$this->object = new Oauth2(
			self::IBMID_ENDPOINT_BASE_URL,
			self::IBMID_CLIENT_ID,
			self::IBMID_CLIENT_SECRET,
			self::STATE,
			$this->session,
			$this->httpClient,
			$this->jwtParser
		);
	}

	public function testAuthorize()
	{
		$response = Stub::make('\Slim\Http\Response');

		$response->

		$this->object->authorize($response);
	}
}
