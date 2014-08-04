<?php
namespace OAuth\OAuth2\Service;

use OAuth\OAuth2\Token\StdOAuth2Token;
use OAuth\Common\Http\Exception\TokenResponseException;
use OAuth\Common\Http\Uri\Uri;
use OAuth\Common\Consumer\Credentials;
use OAuth\Common\Http\Client\ClientInterface;
use OAuth\Common\Storage\TokenStorageInterface;
use OAuth\Common\Http\Uri\UriInterface;
use OAuth\Common\Token\TokenInterface;
use OAuth\Common\Token\Exception\ExpiredTokenException;

class Odnoklassniki extends AbstractService
{
    protected $applicationKey;

    const PARAMETER_NAME_ACCESS_TOKEN = "access_token";
    const PARAMETER_NAME_REFRESH_TOKEN = "refresh_token";

    public function __construct(Credentials $credentials, ClientInterface $httpClient, TokenStorageInterface $storage, $scopes = array(), UriInterface $baseApiUri = null)
    {
        parent::__construct($credentials, $httpClient, $storage, $scopes, $baseApiUri);
        if( null === $baseApiUri ) {
            $this->baseApiUri = new Uri('http://api.odnoklassniki.ru/fb.do');
        }
    }

    /**
     * @return \OAuth\Common\Http\Uri\UriInterface
     */
    public function getAuthorizationEndpoint()
    {
        return new Uri('http://www.odnoklassniki.ru/oauth/authorize');
    }

    /**
     * @return \OAuth\Common\Http\Uri\UriInterface
     */
    public function getAccessTokenEndpoint()
    {
        return new Uri('http://api.odnoklassniki.ru/oauth/token.do');
    }

    /**
     * @param string $appKey
     * @return $this
     */
    public function setApplicationKey($appKey)
    {
        $this->applicationKey = $appKey;
        return $this;
    }

    /**
     * @return string
     */
    public function getApplicationKey()
    {
        return $this->applicationKey;
    }

    /**
     * @param string $responseBody
     * @return \OAuth\Common\Token\TokenInterface|\OAuth\OAuth2\Token\StdOAuth2Token
     * @throws \OAuth\Common\Http\Exception\TokenResponseException
     */
    protected function parseAccessTokenResponse($responseBody)
    {
        $data = json_decode($responseBody, true);

        if( null === $data || !is_array($data) ) {
            throw new TokenResponseException('Unable to parse response.');
        } elseif( isset($data['error'] ) ) {
            throw new TokenResponseException('Error in retrieving token: "' . $data['error'] . '"');
        }

        $token = new StdOAuth2Token();

        $token->setAccessToken( $data['access_token'] );
        $token->setLifeTime(1800); // token has fixed expire and it's value is not returned by service

        if( isset($data['refresh_token'] ) ) {
            $token->setRefreshToken( $data['refresh_token'] );
            unset($data['refresh_token']);
        }

        unset( $data['access_token'] );

        if ( $this->applicationKey ) {
            $data['application_key'] = $this->applicationKey;
        }
        //unset( $data['expires_in'] );
        $token->setExtraParams( $data );

        return $token;
    }

    /**
     * {@inheritdoc}
     */
    protected function getAuthorizationMethod()
    {
        return self::AUTHORIZATION_METHOD_HEADER_OAUTH;
    }

/* Must implement public function refreshAccessToken(TokenInterface $token)

    public function updateAccessTokenWithRefreshToken(){
        $curl = curl_init($this->getAccessTokenEndpoint());
        curl_setopt($curl, CURLOPT_POST, true);
        curl_setopt($curl, CURLOPT_POSTFIELDS, 'refresh_token=' . self::$refresh_token . '&grant_type=refresh_token&client_id=' . $this->credentials->getConsumerId() . '&client_secret=' . $this->credentials->getConsumerSecret());
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
        $s = curl_exec($curl);
        curl_close($curl);
        $a = json_decode($s, true);
        if (empty($a[self::PARAMETER_NAME_ACCESS_TOKEN])) {
            return false;
        } else {
            self::$access_token = $a[self::PARAMETER_NAME_ACCESS_TOKEN];
            return true;
        }
    }
*/
    private function calcSignature($access_token, $parameters = []){
        if (!count($parameters) && (!self::isAssoc($parameters)))
            return null;

        if (!ksort($parameters)){
            return null;
        } else {
            $requestStr = "";
            foreach($parameters as $key=>$value){
                $requestStr .= $key . "=" . $value;
            }
            $requestStr .= md5($access_token . $this->credentials->getConsumerSecret());
            return md5($requestStr);
        }
    }

    private static function isAssoc($arr){
        return array_keys($arr) !== range(0, count($arr) - 1);
    }

    public function request($path, $method = 'GET', $body = null, array $extraHeaders = array())
    {
        $uri = $this->baseApiUri;

        $token = $this->storage->retrieveAccessToken($this->service());
        $extraHeaders = $token->getExtraParams();

        if( ( $token->getEndOfLife() !== TokenInterface::EOL_NEVER_EXPIRES ) &&
            ( $token->getEndOfLife() !== TokenInterface::EOL_UNKNOWN ) &&
            ( time() > $token->getEndOfLife() ) ) {
            throw new ExpiredTokenException(
                'Token expired on ' . date('m/d/Y', $token->getEndOfLife()) . ' at ' . date('h:i:s A', $token->getEndOfLife())
            );
        }

        $parameters = [
            'application_key' => $this->credentials->getConsumerPublic(),
            'method' => $path
        ];

        $parameters['sig'] = $this->calcSignature($token->getAccessToken(),  $parameters);
        $parameters[self::PARAMETER_NAME_ACCESS_TOKEN] = $token->getAccessToken();

        foreach($parameters as $key=>$value){
            $uri->addToQuery($key, urlencode($value));
        }

        return $this->httpClient->retrieveResponse($uri, $body, $extraHeaders, $method);
    }


}