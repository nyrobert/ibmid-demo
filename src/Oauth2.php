<?php

namespace App;

use Psr\Http\Message\ServerRequestInterface as Request;

class Oauth2
{
	/**
	 * @var string
	 */
	private $endpointBaseUrl;

	/**
	 * @var string
	 */
	private $clientId;

	/**
	 * @var string
	 */
	private $clientSecret;

	/**
	 * @var Session
	 */
	private $session;

	/**
	 * @var string
	 */
	private $redirectUrl = 'https://peaceful-wildwood-33778.herokuapp.com/callback';

	public function __construct($endpointBaseUrl, $clientId, $clientSecret, $session)
	{
		$this->endpointBaseUrl = $endpointBaseUrl;
		$this->clientId        = $clientId;
		$this->clientSecret    = $clientSecret;
		$this->session         = $session;
	}

	public static function create()
	{
		return new self(
			getenv('IBMID_ENDPOINT_BASE_URL'),
			getenv('IBMID_CLIENT_ID'),
			getenv('IBMID_CLIENT_SECRET'),
			new Session()
		);
	}

	public function authorize()
	{
		$this->session->set('state', md5(uniqid(mt_rand(), true)));

		$queryParams = [
			'client_id'     => $this->clientId,
			'redirect_url'  => $this->redirectUrl,
			'scope'         => 'openid',
			'response_type' => 'code',
			'state'         => $this->session->get('state'),
		];

		$url = $this->endpointBaseUrl.'/authorize?'.http_build_query($queryParams);

		header('Location: '.$url);
		die();
	}

	public function callback(Request $request)
	{
		$queryParams = $request->getQueryParams();

		if (isset($queryParams['code'])) {
			if ($queryParams['state'] !== $this->session->get('state')) {
				throw new Error($queryParams['state_not_match']);
			}

			$this->getToken($queryParams['code']);
		} elseif (isset($queryParams['error'])) {
			throw new Error($queryParams['error']);
		} else {
			throw new Error('unknown_error');
		}
	}

	public function getToken($code)
	{
		
	}
}
