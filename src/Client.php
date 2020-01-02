<?php

namespace CoreAlg\SocialLogin;

use Exception;
use CoreAlg\SocialLogin\Providers\AzureProvider;

class Client
{
    protected $configuration;

    protected $supportedDriver = [
        "azure"
    ];

    protected $provider;

    public function __construct(array $configuration)
    {
        $this->configuration = $configuration;

        if(!isset($this->configuration['driver']) || empty($this->configuration['driver'])){
            throw new Exception("No driver given.");
        }

        if(!in_array($this->configuration['driver'], $this->supportedDriver)){
            throw new Exception("Given driver is not supported.");
        }

        $this->initializeProvider();
    }

    private function initializeProvider() :void
    {
        if (session_status() == PHP_SESSION_NONE) {
            session_start();
        }

        if($this->configuration['driver'] === "azure"){
            $this->provider = new AzureProvider($this->configuration);
        }
    }

    public function redirect(array $options = []) :void
    {
        $authorizationUrl = $this->provider->getAuthorizationUrl($options);

        // Redirect to authorization endpoint
        header("Location: {$authorizationUrl}");
        exit();
    }

    public function user()
    {
        return $this->provider->getUser();
    }

    public function getAccessToken()
    {
        return $this->provider->getTokens();
    }
    
}