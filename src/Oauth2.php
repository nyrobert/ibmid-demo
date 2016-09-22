<?php

namespace App;

use Slim\Http\Request;
use Slim\Http\Response;
use GuzzleHttp\Client as HttpClient;
use Lcobucci\JWT\Parser as JwtParser;

/**
 * @see Oauth2Test
 */
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
	) {
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

	public function authorize(Request $request, Response $response)
	{
		$this->session->set('state', $this->state);

		$queryParams = [
			'response_type' => 'code',
			'client_id'     => $this->clientId,
			'redirect_uri'  => $request->getUri()->getBaseUrl() . '/callback',
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

			return $this->getToken($queryParams['code'], $request, $response);
		} elseif (isset($queryParams['error'])) {
			throw new Oauth2Error($queryParams['error']);
		} else {
			throw new Oauth2Error('unknown_error');
		}
	}

	private function getToken($code, Request $request, Response $response)
	{
		$tokenResponse = $this->httpClient->post(
			$this->endpointBaseUrl . '/token',
			[
				'headers' => [
					'Content-Type'  => 'application/x-www-form-urlencoded',
					'Authorization' => 'Basic ' . $this->getEncodedCredentials(),
					'Accept'        => 'application/json',
				],
				'form_params' => [
					'grant_type'   => 'authorization_code',
					'code'         => $code,
					'client_id'    => $this->clientId,
					'redirect_uri' => $request->getUri()->getBaseUrl() . '/callback',
					'scope'        => 'openid',
				],
				'verify' => true,
			]
		);

		$token = \GuzzleHttp\json_decode($tokenResponse->getBody(), true);

		if (isset($token['access_token']) && isset($token['id_token'])) {
			$this->session->reGenerateId();
			$this->session->set(
				'user',
				[
					'id'    => $this->getIdClaim((string) $token['id_token']),
					'email' => $this->getEmailClaim((string) $token['id_token'])
				]
			);
			return $response->withRedirect($request->getUri()->getBaseUrl());
		} elseif (isset($token['error'])) {
			throw new Oauth2Error($token['error']);
		} else {
			throw new Oauth2Error('unknown_error');
		}
	}

	private function getEncodedCredentials()
	{
		return base64_encode($this->clientId . ':' . $this->clientSecret);
	}

	private function getIdClaim($idToken)
	{
		return $this->jwtParser->parse($idToken)->getClaim('sub');
	}

	private function getEmailClaim($idToken)
	{
		return $this->jwtParser->parse($idToken)->getClaim('email');
	}

	private static function generateState()
	{
		return md5(uniqid(mt_rand(), true));
	}
}
