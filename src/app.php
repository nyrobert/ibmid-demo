<?php

use App\Oauth2;
use App\Session;
use \Psr\Http\Message\ServerRequestInterface as Request;
use \Psr\Http\Message\ResponseInterface as Response;

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
	return $this->view->render($response, 'index.html.twig');
});

$app->get('/authorize', function (Request $request, Response $response) {
	Oauth2::create()->authorize();
})->setName('authorize');

$app->get('/callback', function (Request $request, Response $response) {
	Oauth2::create()->authorize();
});

return $app;
