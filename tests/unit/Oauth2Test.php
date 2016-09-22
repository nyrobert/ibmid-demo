<?php

use App\Oauth2;

class Oauth2Test extends \Codeception\Test\Unit
{
	const IBMID_ENDPOINT_BASE_URL = 'https://auth.ibmid.com';
	const IBMID_CLIENT_ID         = 'abcdefgh';
	const IBMID_CLIENT_SECRET     = '123456789';
	const STATE                   = 'abc123';
	const BASE_URL                = 'https://app.com';

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
		$this->session    = $this->getMockBuilder('\App\Session')->getMock();
		$this->httpClient = $this->getMockBuilder('\GuzzleHttp\Client')->getMock();
		$this->jwtParser  = $this->getMockBuilder('\Lcobucci\JWT\Parser')->getMock();
		$this->request    = $this->getMockBuilder('\Slim\Http\Request')->disableOriginalConstructor()->getMock();
		$this->uri        = $this->getMockBuilder('\Slim\Http\Uri')->disableOriginalConstructor()->getMock();
		$this->response   = $this->getMockBuilder('\Slim\Http\Response')->getMock();

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
		$this->session
			->expects($this->once())->method('set');
		$this->session
			->expects($this->once())->method('get')
			->will($this->returnValue(self::STATE));

		$queryParams = [
			'response_type' => 'code',
			'client_id'     => self::IBMID_CLIENT_ID,
			'redirect_uri'  => self::BASE_URL . '/callback',
			'scope'         => 'openid',
			'state'         => self::STATE,
		];

		$url = self::IBMID_ENDPOINT_BASE_URL . '/authorize?' . http_build_query($queryParams);

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

	public function testCallbackWithError()
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
}
