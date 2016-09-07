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
	private $redirectBaseUrl = 'https://peaceful-wildwood-33778.herokuapp.com';

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
		$this->session->set('state', $this->generateState());

		$queryParams = [
			'response_type' => 'code',
			'client_id'     => $this->clientId,
			'redirect_uri'  => $this->redirectBaseUrl.'/callback',
			'scope'         => 'openid',
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
		$headers = [
			'Content-Type: application/x-www-form-urlencoded',
			'Authorization: Basic '.base64_encode($this->clientId.':'.$this->clientSecret),
		];

		$data = [
			'grant_type'   => 'authorization_code',
			'code'         => $code,
			'client_id'    => $this->clientId,
			'redirect_uri' => $this->redirectBaseUrl.'/callback',
			'scope'        => 'openid',
		];

		$curl = curl_init();
		curl_setopt($curl, CURLOPT_URL, $this->endpointBaseUrl.'/token');
		curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
		curl_setopt($curl, CURLOPT_POST, true);
		curl_setopt($curl, CURLOPT_POSTFIELDS, $data);
		curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
		curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($curl, CURLOPT_FOLLOWLOCATION, true);

		$response = curl_exec($curl);

		if ($response === false) {
			$error = curl_error($curl);
			curl_close($curl);
			throw new Error('curl_error:'.$error);
		}

		if (isset($response['access_token']) && isset($response['id_token'])) {
			$this->session->reGenerateId();
			$this->session->set('user', $response['id_token']);
			header('Location: '.$this->redirectBaseUrl);
		}
	}

	private function generateState()
	{
		return md5(uniqid(mt_rand(), true));
	}
}
