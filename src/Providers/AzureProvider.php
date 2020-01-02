<?php

namespace CoreAlg\SocialLogin\Providers;

use Exception;
use League\OAuth2\Client\Provider\GenericProvider;
use stdClass;

const OAUTH_AUTHORITY = "https://login.microsoftonline.com/common";
const OAUTH_AUTHORIZE_ENDPOINT = "/oauth2/v2.0/authorize";
const OAUTH_TOKEN_ENDPOINT = "/oauth2/v2.0/token";

class AzureProvider
{
    protected $configuration;
    protected $provider;

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
            "urlAuthorize" => OAUTH_AUTHORITY.OAUTH_AUTHORIZE_ENDPOINT,
            "urlAccessToken" => OAUTH_AUTHORITY.OAUTH_TOKEN_ENDPOINT,
            "urlResourceOwnerDetails" => "",
            "scopes" => $this->configuration["scopes"],
        ]);
    }

    public function getAuthorizationUrl(array $options = []) :string
    {
        $authorizationUrl = $this->provider->getAuthorizationUrl($options);

        // Get the state generated for you and store it to the session.
        $_SESSION['oauth2state'] = $this->provider->getState();

        return $authorizationUrl;
    }

    public function checkState() :bool
    {
        $flag = true;

        if (empty($_GET['state']) || ($_GET['state'] !== $_SESSION['oauth2state'])) {
            $flag = false;
        }

        return $flag;
    }

    public function getCode() :string
    {
        if(!isset($_GET["code"]) || isset($_GET['error'])){
            // "ERROR:  {$_GET['error']} - {$_GET['error_description']}"
            return "";
        }

        if($this->checkState() === false){
            // State provided in redirect does not match expected value.
            return "";
        }

        unset($_SESSION['oauth2state']);

        return $_GET["code"];
    }

    public function getTokens() :array
    {
        $tokens = [];

        $code = $this->getCode();

        try {

            $accessToken = $this->provider->getAccessToken("authorization_code", [
                "code" => $code
            ]);

            $tokens["accessToken"] = $accessToken->getToken();
            $tokens["refreshToken"] = $accessToken->getRefreshToken();
            $tokens["expires"] = $accessToken->getExpires();

        } catch (Exception $ex) {
            // Error
        }

        return $tokens;
    }

    public function getUser()
    {
        $userObject = new stdClass();
        $userObject->id = null;
        $userObject->first_name = null;
        $userObject->last_name = null;
        $userObject->full_name = null;
        $userObject->username = null;
        $userObject->email = null;
        $userObject->gender = null;
        $userObject->age = null;
        $userObject->access_token = null;

        $token = $this->getTokens();

        $accessToken = $token["accessToken"] ?? null;

        if (is_null($accessToken) === true) {
            // Failed to get access token.
            return $userObject;
        }

        $userObject->access_token = json_encode($token);

        try{
            $graph = new \Microsoft\Graph\Graph();
            $graph->setAccessToken($accessToken);

            $user = $graph->createRequest("GET", "/me")
                ->setReturnType(\Microsoft\Graph\Model\User::class)
                ->execute();

            list($first_name, $last_name) = explode(" ", $user->getDisplayName());
            
            $userObject->id = $user->getId();

            $userObject->full_name = "{$first_name} {$last_name}";
            $userObject->first_name = $first_name;
            $userObject->last_name = $last_name;
            $userObject->email = $user->getUserPrincipalName();

        }catch(Exception $ex){
            // Error
        }

        return (array)$userObject;
    }
}