<?php
/**
 * DokuWiki Plugin oauthpdo (Auth Component)
 *
 * @license GPL 2 http://www.gnu.org/licenses/gpl-2.0.html
 * @author  Andreas Gohr <andi@splitbrain.org>
 */

// must be run within Dokuwiki
if(!defined('DOKU_INC')) die();

class auth_plugin_oauthpdo extends auth_plugin_authpdo {

    /**
     * Constructor
     *
     * Sets capabilities.
     */
    public function __construct() {
        parent::__construct();

        $this->cando['external'] = true;
    }

    private function handleState($state) {
        error_log('auth::handleState');

        /** @var \helper_plugin_farmer $farmer */
        $farmer = plugin_load('helper', 'farmer', false, true);
        $data = json_decode(base64_decode(urldecode($state)));
        if (empty($data->animal) || $farmer->getAnimal() == $data->animal) {
            return;
        }
        $animal = $data->animal;
        $allAnimals = $farmer->getAllAnimals();
        if (!in_array($animal, $allAnimals)) {
            msg('Animal ' . $animal . ' does not exist!');
            return;
        }
        global $INPUT;
        $url = $farmer->getAnimalURL($animal) . '/doku.php?' . $INPUT->server->str('QUERY_STRING');
        send_redirect($url);
    }

    /**
     * Handle the login
     *
     * This either trusts the session data (if any), processes the second oAuth step or simply
     * executes a normal plugin against local users.
     *
     * @param string $user
     * @param string $pass
     * @param bool   $sticky
     * @return bool
     */
    function trustExternal($user, $pass, $sticky = false) {
        global $USERINFO, $INPUT;

        error_log('auth::trustExternal');

        if ($INPUT->has('state') && plugin_load('helper', 'farmer', false, true)) {
            $this->handleState($INPUT->str('state'));
        }

        // check session for existing oAuth login data
        $session = $_SESSION[DOKU_COOKIE]['auth'];
        if(isset($session['oauthpdo'])) {
            $servicename = $session['oauthpdo'];
            // check if session data is still considered valid
            if ($this->isSessionValid($session)) {
                $_SERVER['REMOTE_USER'] = $session['user'];
                $USERINFO               = $session['info'];
                if (isset($_SESSION[DOKU_COOKIE]['oauthpdo-inprogress']) &&
                    isset($_SESSION[DOKU_COOKIE]['oauthpdo-inprogress']['addNew']) &&
                    $_SESSION[DOKU_COOKIE]['oauthpdo-inprogress']['addNew']
                ) {
                    $addNewLogin = true;
                } else {
                    // Check for oauthremove flag
                    $servicename = $INPUT->str('oauthremove');
                    if ($servicename) {
                        $hlp     = plugin_load('helper', 'oauthpdo');
                        $service     = $hlp->loadService($servicename);
                        if (!is_null($service)) {
                            // remove the oauth entry in-place before doing any other action
                            return $this->oauthRemove($servicename, $INPUT->str('email'));
                        }
                    }
                    return true;
                }
            }
        }

        $existingLoginProcess = false;
        // are we in login progress?
        if(isset($_SESSION[DOKU_COOKIE]['oauthpdo-inprogress'])) {
            $servicename = $_SESSION[DOKU_COOKIE]['oauthpdo-inprogress']['service'];
            $page        = $_SESSION[DOKU_COOKIE]['oauthpdo-inprogress']['id'];
            $params      = $_SESSION[DOKU_COOKIE]['oauthpdo-inprogress']['params'];

            unset($_SESSION[DOKU_COOKIE]['oauthpdo-inprogress']);
            $existingLoginProcess = true;
        }

        // either we're in oauthpdo login or a previous log needs to be rechecked
        if(isset($servicename)) {
            /** @var helper_plugin_oauthpdo $hlp */
            $hlp     = plugin_load('helper', 'oauthpdo');

            /** @var OAuth\Plugin\AbstractAdapter $service */
            $service = $hlp->loadService($servicename);
            if(is_null($service)) {
                $this->cleanLogout();
                return false;
            }

            if($service->checkToken()) {
                $ok = $this->processLogin($sticky, $service, $servicename, $page, $params, $addNewLogin);
                if (!$ok && !$addNewLogin) {
                    $this->cleanLogout();
                    return false;
                }
                return true;
            } else {
                if ($existingLoginProcess) {
                    msg($this->getLang('oauthpdo login failed'),0);
                    if (!$addNewLogin) {
                        $this->cleanLogout();
                        return false;
                    }
                } else {
                    // first time here
                    $this->relogin($servicename);
                }
            }

            $this->cleanLogout();
            return false; // something went wrong during oAuth login
        } elseif (isset($_COOKIE[DOKU_COOKIE])) {
            global $INPUT;
            //try cookie
            list($cookieuser, $cookiesticky, $auth, $servicename) = explode('|', $_COOKIE[DOKU_COOKIE]);
            $cookieuser = base64_decode($cookieuser, true);
            $auth = base64_decode($auth, true);
            $servicename = base64_decode($servicename, true);
            if ($auth === 'oauthpdo') {
                $this->relogin($servicename);
            }
        }

        // do the "normal" plain auth login via form
        return auth_login($user, $pass, $sticky);
    }

    protected function oauthRemove (string $serviceName, string $email = NULL) {
        global $USERINFO;
        if (isset($USERINFO['linkedAccounts'][strtolower($serviceName)])) {
            $linkedAccounts =& $USERINFO['linkedAccounts'][strtolower($serviceName)];
            $key = array_search($email, $linkedAccounts);
            if ($key !== FALSE) {
                $sql = $this->getConf('remove-linked-emails');
                $result = $this->_query($sql, array(
                    ':uid' => $USERINFO['uid'],
                    ':service' => strtolower($serviceName),
                    ':email' => $email
                ));
                if ($result) {
                    array_splice($linkedAccounts, $key, 1);
                    $this->updateUserSessionInfo($USERINFO);
                    $_SESSION[DOKU_COOKIE]['oauthpdo-done']['do'] = 'profile';
                    return TRUE;
                }
            }
        }
        msg($this->getLang('wrongEmailToUnlink'), -1);
        return TRUE;
    }

    /**
     * @param array $session cookie auth session
     *
     * @return bool
     */
    protected function isSessionValid ($session) {
        /** @var helper_plugin_oauthpdo $hlp */
        $hlp     = plugin_load('helper', 'oauthpdo');
        if ($hlp->validBrowserID($session)) {
            if (!$hlp->isSessionTimedOut($session)) {
                return true;
            } elseif (!($hlp->isGETRequest() && $hlp->isDokuPHP())) {
                // only force a recheck on a timed-out session during a GET request on the main script doku.php
                return true;
            }
        }
        return false;
    }

    protected function relogin($servicename) {
        global $INPUT;

        /** @var helper_plugin_oauthpdo $hlp */
        $hlp     = plugin_load('helper', 'oauthpdo');
        $service     = $hlp->loadService($servicename);
        if(is_null($service)) return false;

        // remember service in session
        session_start();
        $_SESSION[DOKU_COOKIE]['oauthpdo-inprogress']['service'] = $servicename;
        $_SESSION[DOKU_COOKIE]['oauthpdo-inprogress']['id']      = $INPUT->str('id');
        $_SESSION[DOKU_COOKIE]['oauthpdo-inprogress']['params']  = $_GET;

        $_SESSION[DOKU_COOKIE]['oauthpdo-done']['$_REQUEST'] = $_REQUEST;

        if (is_array($INPUT->post->param('do'))) {
            $doPost = key($INPUT->post->arr('do'));
        } else {
            $doPost = $INPUT->post->str('do');
        }
        $doGet = $INPUT->get->str('do');
        if (!empty($doPost)) {
            $_SESSION[DOKU_COOKIE]['oauthpdo-done']['do'] = $doPost;
        } elseif (!empty($doGet)) {
            $_SESSION[DOKU_COOKIE]['oauthpdo-done']['do'] = $doGet;
        }

        session_write_close();

        $service->login();
    }

    /**
     * @param                              $sticky
     * @param OAuth\Plugin\AbstractAdapter $service
     * @param string                       $servicename
     * @param string                       $page
     * @param array                        $params
     * @param bool                         $addNew
     *
     * @return bool
     */
    protected function processLogin($sticky, $service, $servicename, $page, $params = array(), $addNew = false) {
        $uinfo = $service->getUser();
        $ok = $this->processUser($uinfo, $servicename, $addNew);
        error_log('auth::processLogin');
        if(!$ok) {
            return false;
        }
        if ($addNew) {
            global $USERINFO;
            $_SESSION[DOKU_COOKIE]['oauthpdo-done']['do'] = 'profile';
            $this->updateUserSessionInfo($USERINFO);
        } else {
            error_log(json_encode($uinfo, JSON_PRETTY_PRINT));
            $this->setUserSession($uinfo, $servicename);
            $this->setUserCookie($uinfo['user'], $sticky, $servicename);
        }
        if(isset($page)) {
            if(!empty($params['id'])) unset($params['id']);
            send_redirect(wl($page, $params, false, '&'));
        }
        return true;
    }

    /**
     * process the user and update the $uinfo array
     *
     * @param $uinfo
     * @param $servicename
     * @param bool $addNew
     *
     * @return bool
     */
    protected function processUser(&$uinfo, $servicename, $addNew = false) {
        $uinfo['user'] = (string) $uinfo['user'];
        $servicename = strtolower($servicename);
        $actionDesc = $addNew ? "link your account" : "log you in";
        error_log('processUser: ' . $addNew);
        if(!$uinfo['name']) $uinfo['name'] = $uinfo['user'];

        if(!$uinfo['user'] || !$uinfo['mail']) {
            msg("$servicename did not provide the needed user info. Can't " . $actionDesc, -1);
            return false;
        }

        // see if the user is known already
        if ($addNew) {
            global $USERINFO;
            $user = $this->getUserByEmail($uinfo['mail'], $servicename);
            if ($user) {
                if ($user !== $_SESSION[DOKU_COOKIE]['auth']['user']) {
                    msg($this->getLang('serviceAlreadyLinked'), -1);
                }
                return false;
            }
            $sql = $this->getConf('add-linked-emails');
            $mail = strtolower($uinfo['mail']);
            error_log(json_encode($USERINFO, JSON_PRETTY_PRINT));
            $result = $this->_query($sql, array_merge($USERINFO, array(':email' => $mail, ':service' => $servicename)));
            if (!$result) {
                msg($this->getLang('cannotAddLinkedEmail'), -1);
                return false;
            } else {
                $USERINFO['linkedAccounts'][$servicename] []= $mail;
            }
        } else {
            // regular login
            $user = $this->getUserByEmail($uinfo['mail'], $servicename);
            if ($user) {
                $sinfo = $this->getUserData($user);
                $mergedGroups = array_merge((array) $uinfo['grps'], $sinfo['grps']);
                $uinfo = array_merge($uinfo, $sinfo);
                $uinfo['user'] = $user;
                $uinfo['grps'] = $mergedGroups;
            } elseif (actionOK('register')) {
                $ok = $this->addUser($uinfo, $servicename);
                if(!$ok) {
                    msg('something went wrong creating your user account. please try again later.', -1);
                    return false;
                }
            } else {
                msg($this->getLang('addUser not possible'), -1);
                return false;
            }
        }
        return true;
    }

    /**
     * new user, create him - making sure the login is unique by adding a number if needed
     *
     * @param array $uinfo user info received from the oAuth service
     * @param string $servicename
     *
     * @return bool
     */
    protected function addUser(&$uinfo, $servicename) {
        global $conf;
        $user = $uinfo['user'];
        $count = '';
        while($this->getUserData($user . $count)) {
            if($count) {
                $count++;
            } else {
                $count = 1;
            }
        }
        $user = $user . $count;
        $uinfo['user'] = $user;
        $groups_on_creation = array();
        $groups_on_creation[] = $conf['defaultgroup'];
        $groups_on_creation[] = $servicename; // add service as group
        $uinfo['grps'] = array_merge((array) $uinfo['grps'], $groups_on_creation);

        $ok = $this->triggerUserMod(
            'create',
            array($user, auth_pwgen($user), $uinfo['name'], $uinfo['mail'], $groups_on_creation,)
        );
        if(!$ok) {
            return false;
        }

        // send notification about the new user
        $subscription = new Subscription();
        $subscription->send_register($user, $uinfo['name'], $uinfo['mail']);
        return true;
    }

    /**
     * Find a user by his email address
     *
     * @param $mail
     * @param $service - the service the user is using
     * @return bool|string
     */
    protected function getUserByEmail($mail, $servicename = null) {
        if ($servicename) {
            $sql = $this->getConf('select-user-from-email-with-service');
            $mail = strtolower($mail);
            $result = $this->_query($sql, array(':mail' => $mail, ':service' => $servicename));
            if ($result) {
                return $result[0]['user'];
            }
        } else {
            $sql = $this->getConf('select-user-from-email');
            $mail = strtolower($mail);
            $result = $this->_query($sql, array(':mail' => $mail));
            if ($result) {
                return $result[0]['user'];
            }
        }
        return false;
    }

    /**
     * @param array  $data
     * @param string $service
     */
    protected function setUserSession($data, $service) {
        global $USERINFO;
        global $conf;

        // set up groups
        if(!is_array($data['grps'])) {
            $data['grps'] = array();
        }
        $data['grps']   = array_unique($data['grps']);

        $USERINFO                               = $data;
        error_log(json_encode($USERINFO, JSON_PRETTY_PRINT));
        $_SERVER['REMOTE_USER']                 = $data['user'];
        $_SESSION[DOKU_COOKIE]['auth']['user']  = $data['user'];
        $_SESSION[DOKU_COOKIE]['auth']['pass']  = $data['pass'];
        $this->updateUserSessionInfo($USERINFO);
        $_SESSION[DOKU_COOKIE]['auth']['buid']  = auth_browseruid();
        $_SESSION[DOKU_COOKIE]['auth']['time']  = time();
        $_SESSION[DOKU_COOKIE]['auth']['oauthpdo'] = $service;
    }

    protected function updateUserSessionInfo ($userInfo) {
        $_SESSION[DOKU_COOKIE]['auth']['info']  = $userInfo;
    }

    /**
     * @param string $user
     * @param bool   $sticky
     * @param string $servicename
     * @param int    $validityPeriodInSeconds optional, per default 1 Year
     */
    private function setUserCookie($user, $sticky, $servicename, $validityPeriodInSeconds = 31536000) {
        $cookie = base64_encode($user).'|'.((int) $sticky).'|'.base64_encode('oauthpdo').'|'.base64_encode($servicename);
        $cookieDir = empty($conf['cookiedir']) ? DOKU_REL : $conf['cookiedir'];
        $time      = $sticky ? (time() + $validityPeriodInSeconds) : 0;
        setcookie(DOKU_COOKIE,$cookie, $time, $cookieDir, '',($conf['securecookie'] && is_ssl()), true);
    }

    /**
     * Unset additional stuff in session on logout
     */
    public function logOff() {
        error_log('auth::logOff');

        parent::logOff();

        $this->cleanLogout();
    }

    /**
     * unset auth cookies and session information
     */
    private function cleanLogout() {
        if(isset($_SESSION[DOKU_COOKIE]['oauthpdo-done'])) {
            unset($_SESSION[DOKU_COOKIE]['oauthpdo-done']);
        }
        if(isset($_SESSION[DOKU_COOKIE]['auth'])) {
            unset($_SESSION[DOKU_COOKIE]['auth']);
        }
        $this->setUserCookie('',true,'',-60);
    }

    /**
     * Enhance function to check against duplicate emails
     *
     * @param string $user
     * @param string $pwd
     * @param string $name
     * @param string $mail
     * @param null   $grps
     * @return bool|null|string
     */
    public function createUser($user, $pwd, $name, $mail, $grps = null) {
        if($this->getUserByEmail($mail)) {
            msg($this->getLang('emailduplicate'), -1);
            return false;
        }

        return parent::createUser($user, $pwd, $name, $mail, $grps);
    }

    /**
     * Enhance function to check aainst duplicate emails
     *
     * @param string $user
     * @param array  $changes
     * @return bool
     */
    public function modifyUser($user, $changes) {
        global $conf;

        if(isset($changes['mail'])) {
            $found = $this->getUserByEmail($changes['mail']);
            if($found != $user) {
                msg($this->getLang('emailduplicate'), -1);
                return false;
            }
        }

        $ok = parent::modifyUser($user, $changes);

        // refresh session cache
        touch($conf['cachedir'] . '/sessionpurge');

        return $ok;
    }

    public function getUserData ($user, $requireGroups = true) {
        $data = parent::getUserData($user, $requireGroups);
        $sql = $this->getConf('get-user-linked-emails');
        $linkedAccounts = array();
        $result = $this->_query($sql, $data);
        if ($result) {
            foreach ($result as $row) {
                if (!isset($linkedAccounts[strtolower($row['service'])])) {
                    $linkedAccounts[strtolower($row['service'])] = [];
                } 
                $linkedAccounts[strtolower($row['service'])] []= $row['email'];
            }
            unset($row);
        }
        $data['linkedAccounts'] = $linkedAccounts;
        return $data;
    }

}

// vim:ts=4:sw=4:et:
