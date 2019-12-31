<?php

namespace CoreAlg\SocialLogin\Providers;

use Exception;
use League\OAuth2\Client\Provider\GenericProvider;

class AzureProvider
{
    protected $configuration;
    protected $provider;

    private $OAUTH_AUTHORITY = "https://login.microsoftonline.com/common";
    private $OAUTH_AUTHORIZE_ENDPOINT = "/oauth2/v2.0/authorize";
    private $OAUTH_TOKEN_ENDPOINT = "/oauth2/v2.0/token";

    public function __construct($configuration)
    {
        $this->configuration = $configuration;

        $this->initialize();
    }

    private function initialize() :void
    {
        $this->provider = new GenericProvider([
            "clientId" => $this->configuration["client_id"],
            "clientSecret" => $this->configuration["client_secret"],
            "redirectUri" => $this->configuration["callback_url"],
            'urlAuthorize' => "{$this->OAUTH_AUTHORITY}{$this->OAUTH_AUTHORIZE_ENDPOINT}",
            'urlAccessToken' => "{$this->OAUTH_AUTHORITY}{$this->OAUTH_TOKEN_ENDPOINT}",
            'urlResourceOwnerDetails' => '',
            "scopes" => $this->configuration["scopes"],
        ]);
    }

    public function getAuthorizationUrl() :string
    {
        return $this->provider->getAuthorizationUrl();
    }

    public function getAccessToken() :string
    {
        try {
            $accessToken = $this->provider->getAccessToken('authorization_code', [
                'code' => $_GET['code']
            ]);
        } catch (Exception $ex) {
            $accessToken = "";
        }

        return $accessToken;
    }

    public function getUser()
    {
        $accessToken = $this->getAccessToken();

        $graph = new \Microsoft\Graph\Graph();
        $graph->setAccessToken($accessToken);

        $user = $graph->createRequest("GET", "/me")
            ->setReturnType(\Microsoft\Graph\Model\User::class)
            ->execute();

        return [
            "id" => $user->getId(),
            "name" => $user->getDisplayName(),
            "email" => $user->getUserPrincipalName()
        ];
    }
}