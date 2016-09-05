<?php

use \Psr\Http\Message\ServerRequestInterface as Request;
use \Psr\Http\Message\ResponseInterface as Response;

$app = new \Slim\App;

$app->get('/', function (Request $request, Response $response) {
	$oidc = new OpenIDConnectClient(
		'hhttps://accounts.google.com/o/oauth2/v2/auth',
		'392849214846-iuqevu02aa5so05ps614kfqce1ggbhc7.apps.googleusercontent.com',
		'jCXn7SuU_uuoKMTx2e6P7NNw'
	);

	$oidc->authenticate();

	$email = $oidc->requestUserInfo('email');

	$response->getBody()->write('Hello '.$email);

	return $response;
});

return $app;
