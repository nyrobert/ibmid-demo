<?php

use App\Session;
use App\Oauth2;
use Slim\App;
use Slim\Http\Request;
use Slim\Http\Response;

$session = new Session();
$session->start();

$config = [
	'settings' => [
		'displayErrorDetails' => true,
	],
];

$app = new App($config);

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

$app->get('/authorize', function (Request $request, Response $response) {
	return Oauth2::create()->authorize($request, $response);
})->setName('authorize');

$app->get('/callback', function (Request $request, Response $response) {
	try {
		return Oauth2::create()->callback($request, $response);
	} catch (\Exception $e) {
		return $response->withRedirect(
			$request->getUri()->getBaseUrl() . '?' . http_build_query(['error' => $e->getMessage()]),
			401
		);
	}
});

$app->get('/logout', function (Request $request, Response $response) use ($session) {
	$session->destroy();
	return $response->withRedirect($request->getUri()->getBaseUrl());
})->setName('logout');

return $app;
