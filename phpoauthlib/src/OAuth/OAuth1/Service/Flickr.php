<?php

namespace OAuth\OAuth1\Service;

use OAuth\OAuth1\Signature\SignatureInterface;
use OAuth\OAuth1\Token\StdOAuth1Token;
use OAuth\Common\Http\Exception\TokenResponseException;
use OAuth\Common\Http\Uri\Uri;
use OAuth\Common\Consumer\CredentialsInterface;
use OAuth\Common\Http\Uri\UriInterface;
use OAuth\Common\Storage\TokenStorageInterface;
use OAuth\Common\Http\Client\ClientInterface;

class Flickr extends AbstractService
{
    
    public function __construct(
        CredentialsInterface $credentials,
        ClientInterface $httpClient,
        TokenStorageInterface $storage,
        SignatureInterface $signature,
        UriInterface $baseApiUri = null
    ) {
        parent::__construct($credentials, $httpClient, $storage, $signature, $baseApiUri);
        if ($baseApiUri === null) {
            $this->baseApiUri = new Uri('https://api.flickr.com/services/rest/');
        }
    }
    
    public function getRequestTokenEndpoint()
    {
        return new Uri('https://www.flickr.com/services/oauthpdo/request_token');
    }
    
    public function getAuthorizationEndpoint()
    {
        return new Uri('https://www.flickr.com/services/oauthpdo/authorize');
    }
    
    public function getAccessTokenEndpoint()
    {
        return new Uri('https://www.flickr.com/services/oauthpdo/access_token');
    }
    
    protected function parseRequestTokenResponse($responseBody)
    {
        parse_str($responseBody, $data);
        if (null === $data || !is_array($data)) {
            throw new TokenResponseException('Unable to parse response.');
        } elseif (!isset($data['oauthpdo_callback_confirmed']) || $data['oauthpdo_callback_confirmed'] != 'true') {
            throw new TokenResponseException('Error in retrieving token.');
        }
        return $this->parseAccessTokenResponse($responseBody);
    }
    
    protected function parseAccessTokenResponse($responseBody)
    {
        parse_str($responseBody, $data);
        if ($data === null || !is_array($data)) {
            throw new TokenResponseException('Unable to parse response.');
        } elseif (isset($data['error'])) {
            throw new TokenResponseException('Error in retrieving token: "' . $data['error'] . '"');
        }
        
        $token = new StdOAuth1Token();
        $token->setRequestToken($data['oauthpdo_token']);
        $token->setRequestTokenSecret($data['oauthpdo_token_secret']);
        $token->setAccessToken($data['oauthpdo_token']);
        $token->setAccessTokenSecret($data['oauthpdo_token_secret']);
        $token->setEndOfLife(StdOAuth1Token::EOL_NEVER_EXPIRES);
        unset($data['oauthpdo_token'], $data['oauthpdo_token_secret']);
        $token->setExtraParams($data);
        
        return $token;
    }
    
    public function request($path, $method = 'GET', $body = null, array $extraHeaders = array())
    {
        $uri = $this->determineRequestUriFromPath('/', $this->baseApiUri);
        $uri->addToQuery('method', $path);
        
        $token = $this->storage->retrieveAccessToken($this->service());
        $extraHeaders = array_merge($this->getExtraApiHeaders(), $extraHeaders);
        $authorizationHeader = array(
            'Authorization' => $this->buildAuthorizationHeaderForAPIRequest($method, $uri, $token, $body)
        );
        $headers = array_merge($authorizationHeader, $extraHeaders);
        
        return $this->httpClient->retrieveResponse($uri, $body, $headers, $method);
    }
}
