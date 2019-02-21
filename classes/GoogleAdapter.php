<?php

namespace OAuth\Plugin;

use OAuth\OAuth2\Service\Google;

class GoogleAdapter extends AbstractAdapter {

    /**
     * Retrieve the user's data
     *
     * The array needs to contain at least 'user', 'email', 'name' and optional 'grps'
     *
     * @return array
     */
    public function getUser() {
        $JSON = new \JSON(JSON_LOOSE_TYPE);
        $data = array();

        $result = $JSON->decode($this->oAuth->request('https://www.googleapis.com/oauth2/v1/userinfo'));

        $data['user'] = $result['name'];
        $data['name'] = $result['name'];
        $data['mail'] = $result['email'];
        
        // Additional info from Google People API: alternative emails
        $data['altEmails'] = array();
        
        try {
            $result = $JSON->decode($this->oAuth->request('https://people.googleapis.com/v1/people/me?personFields=emailAddresses'));
            if (is_array($result['emailAddresses'])) {
                foreach ($result['emailAddresses'] as $emailEntry) {
                    if ($emailEntry['value'] !== $data['mail']) {
                        $data['altEmails'] []= $emailEntry['value'];
                    }
                }
            }
        } catch (Exception $e) {
            error_log('Error connecting to Google People API: code may be obselete.\nException: ' .
                $e->getMessage());
        }

        return $data;
    }

    /**
     * Access to user and his email addresses
     *
     * @return array
     */
    public function getScope() {
        return array(Google::SCOPE_USERINFO_EMAIL, Google::SCOPE_USERINFO_PROFILE, Google::SCOPE_ALL_EMAILS);
    }

    public function login($forceNew = false) {
        $parameters = array();
        if(!$forceNew && !empty($_SESSION[DOKU_COOKIE]['auth']['info']['mail'])) {
            $usermail = $_SESSION[DOKU_COOKIE]['auth']['info']['mail'];
            $parameters['login_hint'] = $usermail;
        }

        /** @var \helper_plugin_farmer $farmer */
        $farmer = plugin_load('helper', 'farmer', false, true);
        if ($farmer && $animal = $farmer->getAnimal()) {
            $parameters['state'] = urlencode(base64_encode(json_encode(array('animal'=>$animal,'state'=> md5(rand())))));
            $this->storage->storeAuthorizationState('Google', $parameters['state']);
        }

        if ($forceNew) {
            $parameters['prompt'] = 'select_account';
        }
        $url = $this->oAuth->getAuthorizationUri($parameters);
        send_redirect($url);
    }

}
