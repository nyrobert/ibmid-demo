<?php

namespace App;

use Slim\Http\Request;
use Slim\Http\Response;
use GuzzleHttp\Client as HttpClient;

class Oauth2
{
	const APP_URL = 'https://peaceful-wildwood-33778.herokuapp.com';

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
	 * @var string
	 */
	private $state;

	/**
	 * @var Session
	 */
	private $session;

	/**
	 * @var HttpClient
	 */
	private $httpClient;

	public function __construct(
		$endpointBaseUrl,
		$clientId,
		$clientSecret,
		$state,
		$session,
		$httpClient
	)
	{
		$this->endpointBaseUrl = $endpointBaseUrl;
		$this->clientId        = $clientId;
		$this->clientSecret    = $clientSecret;
		$this->state           = $state;
		$this->session         = $session;
		$this->httpClient      = $httpClient;
	}

	public static function create()
	{
		return new self(
			getenv('IBMID_ENDPOINT_BASE_URL'),
			getenv('IBMID_CLIENT_ID'),
			getenv('IBMID_CLIENT_SECRET'),
			self::generateState(),
			new Session(),
			new HttpClient()
		);
	}

	public function authorize(Response $response)
	{
		$this->session->set('state', $this->state);

		$queryParams = [
			'response_type' => 'code',
			'client_id'     => $this->clientId,
			'redirect_uri'  => self::APP_URL . '/callback',
			'scope'         => 'openid',
			'state'         => $this->session->get('state'),
		];

		$url = $this->endpointBaseUrl . '/authorize?' . http_build_query($queryParams);

		$response->withRedirect($url);
		exit();
	}

	public function callback(Request $request, Response $response)
	{
		$queryParams = $request->getQueryParams();

		if (isset($queryParams['code'])) {
			if ($queryParams['state'] !== $this->session->get('state')) {
				throw new Oauth2Error($queryParams['invalid_state']);
			}

			$this->getToken($queryParams['code'], $response);
		} elseif (isset($queryParams['error'])) {
			throw new Oauth2Error($queryParams['error']);
		} else {
			throw new Oauth2Error('unknown_error');
		}
	}

	public function getToken($code, Response $response)
	{
		$credentials = base64_encode($this->clientId . ':' . $this->clientSecret);

		$tokenResponse = $this->httpClient->post(
			$this->endpointBaseUrl . '/token', [
				'headers' => [
					'Content-Type'  => 'application/x-www-form-urlencoded',
					'Authorization' => 'Basic ' . $credentials,
					'Accept'        => 'application/json',
				],
				'form_params' => [
					'grant_type'   => 'authorization_code',
					'code'         => $code,
					'client_id'    => $this->clientId,
					'redirect_uri' => self::APP_URL . '/callback',
					'scope'        => 'openid',
				],
				'verify' => true,
			]
		);

		$token = \GuzzleHttp\json_decode($tokenResponse->getBody(), true);

		if (isset($token['access_token']) && isset($token['id_token'])) {
			$this->session->reGenerateId();
			$this->session->set('user', $tokenResponse['id_token']);
			$response->withRedirect(self::APP_URL);
			exit();
		} elseif (isset($token['error'])) {
			throw new Oauth2Error($token['error']);
		} else {
			throw new Oauth2Error('unknown_error');
		}
	}

	private static function generateState()
	{
		return md5(uniqid(mt_rand(), true));
	}
}
