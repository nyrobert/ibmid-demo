<?php

use App\Oauth2;
use App\Session;
use App\Error;
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Message\ResponseInterface as Response;

(new Session())->start();

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

$app->get('/', function (Request $request, Response $response) {
	return $this->view->render($response, 'index.html.twig', ['user' => (new Session())->get('user')]);
});

$app->get('/authorize', function () {
	Oauth2::create()->authorize();
})->setName('authorize');

$app->get('/callback', function (Request $request, Response $response) {
	try {
		Oauth2::create()->callback($request);
	} catch (Error $e) {
		return $this->view->render($response, 'index.html.twig', ['error' => $e->getMessage()]);
	}
});

return $app;
