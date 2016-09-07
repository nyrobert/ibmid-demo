<?php

use App\Session;
use Slim\Http\Request;
use Slim\Http\Response;

const APP_URL = 'https://peaceful-wildwood-33778.herokuapp.com';

$session = new Session();
$session->start();

$config = [
	'settings' => [
		'displayErrorDetails' => true,
	],
];

$app = new \Slim\App($config);

$container = $app->getContainer();
$container['view'] = function ($container) {
	$view = new \Slim\Views\Twig('templates', ['cache' => false]);
	$view->addExtension(new \Slim\Views\TwigExtension(
		$container['router'],
		$container['request']->getUri()
	));
	return $view;
};

$app->get('/', function (Request $request, Response $response) use ($session) {
	return $this->view->render(
		$response,
		'index.html.twig',
		['user' => $session->get('user'), 'error' => $request->getQueryParam('error')]
	);
});

$app->get('/authorize', function () use ($session) {
	$provider = getProvider();

	$authorizationUrl = $provider->getAuthorizationUrl();

	$session->set('oauth2state', $provider->getState());

	header('Location: ' . $authorizationUrl);
	exit;
})->setName('authorize');

$app->get('/callback', function (Request $request, Response $response) use ($session) {
	$provider = getProvider();

	$queryParams = $request->getQueryParams();

	if ($queryParams['error']) {
		error($response, $queryParams['error']);
	}

	if ($queryParams['state'] !== $session->get('oauth2state')) {
		error($response, 'invalid_state');
	}

	if (empty($queryParams['code'])) {
		error($response, 'unknown_error');
	}

	try {
		$accessToken = $provider->getAccessToken('authorization_code', ['code' => $queryParams['code']]);

		$userData = $provider->getResourceOwner($accessToken)->toArray();

		$session->reGenerateId();
		$session->set('user', $userData);

		$response->withRedirect(APP_URL);
		exit;
	} catch (\League\OAuth2\Client\Provider\Exception\IdentityProviderException $e) {
		error($response, $e->getMessage());
	}
});

function getProvider()
{
	return new \League\OAuth2\Client\Provider\GenericProvider([
		'clientId'                => getenv('IBMID_CLIENT_ID'),
		'clientSecret'            => getenv('IBMID_CLIENT_SECRET'),
		'scopes'                  => 'openid',
		'redirectUri'             => APP_URL . '/callback',
		'urlAuthorize'            => getenv('IBMID_ENDPOINT_BASE_URL') . '/authorize',
		'urlAccessToken'          => getenv('IBMID_ENDPOINT_BASE_URL') . '/token',
		'urlResourceOwnerDetails' => getenv('IBMID_ENDPOINT_BASE_URL') . '/introspect',
	]);
}

function error(Response $response, $message)
{
	$response->withRedirect(APP_URL . '?' . http_build_query(['error' => $message]), 401);
	exit;
}

return $app;
