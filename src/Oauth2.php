<?php

namespace App;

use Slim\Http\Request;
use Slim\Http\Response;
use GuzzleHttp\Client as HttpClient;
use Lcobucci\JWT\Parser as JwtParser;

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

	/**
	 * @var JwtParser
	 */
	private $jwtParser;

	public function __construct(
		$endpointBaseUrl,
		$clientId,
		$clientSecret,
		$state,
		$session,
		$httpClient,
		$jwtParser
	)
	{
		$this->endpointBaseUrl = $endpointBaseUrl;
		$this->clientId        = $clientId;
		$this->clientSecret    = $clientSecret;
		$this->state           = $state;
		$this->session         = $session;
		$this->httpClient      = $httpClient;
		$this->jwtParser       = $jwtParser;
	}

	public static function create()
	{
		return new self(
			getenv('IBMID_ENDPOINT_BASE_URL'),
			getenv('IBMID_CLIENT_ID'),
			getenv('IBMID_CLIENT_SECRET'),
			self::generateState(),
			new Session(),
			new HttpClient(),
			new JwtParser()
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

		return $response->withRedirect($url);
	}

	public function callback(Request $request, Response $response)
	{
		$queryParams = $request->getQueryParams();

		if (isset($queryParams['code'])) {
			if ($queryParams['state'] !== $this->session->get('state')) {
				$this->session->remove('state');
				throw new Oauth2Error('invalid_state');
			}

			return $this->getToken($queryParams['code'], $response);
		} elseif (isset($queryParams['error'])) {
			throw new Oauth2Error($queryParams['error']);
		} else {
			throw new Oauth2Error('unknown_error');
		}
	}

	private function getToken($code, Response $response)
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
			$idToken = $this->jwtParser->parse((string) $token['id_token']);

			$this->session->reGenerateId();
			$this->session->set('user', $idToken->getClaim('preferred_username'));
			return $response->withRedirect(self::APP_URL);
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
