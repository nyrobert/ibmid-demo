<?php

use App\Oauth2;

class Oauth2Test extends \Codeception\Test\Unit
{
	const IBMID_ENDPOINT_BASE_URL = 'https://auth.ibmid.com';
	const IBMID_CLIENT_ID         = 'abcdefgh';
	const IBMID_CLIENT_SECRET     = '123456789';
	const STATE                   = 'abc123';
	const BASE_URL                = 'https://app.com';
	const OAUTH2_CODE             = 123;

	/**
	 * @var Oauth2
	 */
	private $object;

	/**
	 * @var PHPUnit_Framework_MockObject_MockObject
	 */
	private $session;

	/**
	 * @var PHPUnit_Framework_MockObject_MockObject
	 */
	private $httpClient;

	/**
	 * @var PHPUnit_Framework_MockObject_MockObject
	 */
	private $jwtParser;

	/**
	 * @var PHPUnit_Framework_MockObject_MockObject
	 */
	private $request;

	/**
	 * @var PHPUnit_Framework_MockObject_MockObject
	 */
	private $uri;

	/**
	 * @var PHPUnit_Framework_MockObject_MockObject
	 */
	private $response;

	/**
	 * @var \UnitTester
	 */
	protected $tester;

	protected function _before()
	{
		$this->session    = $this->createMock('\App\Session');
		$this->httpClient = $this->createMock('\GuzzleHttp\Client');
		$this->jwtParser  = $this->createMock('\Lcobucci\JWT\Parser');
		$this->request    = $this->createMock('\Slim\Http\Request');
		$this->uri        = $this->createMock('\Slim\Http\Uri');
		$this->response   = $this->createMock('\Slim\Http\Response');

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
		$url = self::IBMID_ENDPOINT_BASE_URL . '/authorize?' . http_build_query($this->getQueryParamsForAuthorize());

		$this->session
			->expects($this->once())->method('set');
		$this->session
			->expects($this->once())->method('get')
			->will($this->returnValue(self::STATE));

		$this->uri
			->expects($this->once())->method('getBaseUrl')
			->will($this->returnValue(self::BASE_URL));

		$this->request
			->expects($this->once())->method('getUri')
			->will($this->returnValue($this->uri));

		$this->response
			->expects($this->once())->method('withRedirect')
			->with($url);

		$this->object->authorize($this->request, $this->response);
	}

	public function testCallbackWithStateError()
	{
		$error = 'invalid_state';

		$this->request
			->expects($this->once())->method('getQueryParams')
			->will($this->returnValue(['code' => self::OAUTH2_CODE, 'state' => 'efg123']));

		$this->session
			->expects($this->once())->method('get')
			->will($this->returnValue(self::STATE));
		$this->session
			->expects($this->once())->method('remove');

		$this->expectException('\App\Oauth2Error');
		$this->expectExceptionMessage($error);

		$this->object->callback($this->request, $this->response);
	}

	public function testCallbackWithOauth2Error()
	{
		$error = 'invalid_request';

		$this->request
			->expects($this->once())->method('getQueryParams')
			->will($this->returnValue(['error' => $error]));

		$this->expectException('\App\Oauth2Error');
		$this->expectExceptionMessage($error);

		$this->object->callback($this->request, $this->response);
	}

	public function testCallbackWithUnknownError()
	{
		$error = 'unknown_error';

		$this->request
			->expects($this->once())->method('getQueryParams')
			->will($this->returnValue([]));

		$this->expectException('\App\Oauth2Error');
		$this->expectExceptionMessage($error);

		$this->object->callback($this->request, $this->response);
	}

	private function getQueryParamsForAuthorize()
	{
		return [
			'response_type' => 'code',
			'client_id'     => self::IBMID_CLIENT_ID,
			'redirect_uri'  => self::BASE_URL . '/callback',
			'scope'         => 'openid',
			'state'         => self::STATE,
		];
	}
}