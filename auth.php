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
        /**
         * Procedure:
         * First use Oauth to check if already logged in, or need relogin
         * (this is already implemented by plugin-oauth)
         * Then use auth_login() to check if still logged in, or normal login
         * process.
         * If auth_login() returns TRUE, then check oauthpdo-addnew or
         * oauthremove (if exists), and direct to related procedures.
         */
        global $USERINFO, $INPUT;

        $authenticated = NULL;

        if ($INPUT->has('state') && plugin_load('helper', 'farmer', false, true)) {
            $this->handleState($INPUT->str('state'));
        }

        // check session for existing oAuth login data
        $session = $_SESSION[DOKU_COOKIE]['auth'];
        error_log(json_encode($_SESSION[DOKU_COOKIE], JSON_PRETTY_PRINT));
        if(isset($session['oauthpdo'])) {
            $servicename = $session['oauthpdo'];
            // check if session data is still considered valid
            if ($this->isSessionValid($session)) {
                $_SERVER['REMOTE_USER'] = $session['user'];
                $USERINFO               = $session['info'];
                $authenticated = TRUE;
            }
        }

        if (is_null($authenticated)) {
            $existingLoginProcess = false;
            // are we in login progress?
            if(isset($_SESSION[DOKU_COOKIE]['oauthpdo-inprogress']) &&
                !isset($_SESSION[DOKU_COOKIE]['oauthpdo-inprogress']['addNew'])
            ) {
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
                    $authenticated = FALSE;
                }

                error_log('$service->checkToken(): addnewLogin: ' . $addNewLogin);
                if($service->checkToken()) {
                    $ok = $this->processLogin($sticky, $service, $servicename, $page, $params, $addNewLogin);
                    if (!$ok) {
                        $this->cleanLogout();
                        $authenticated = false;
                    }
                    $authenticated = true;
                } else {
                    if ($existingLoginProcess) {
                        msg($this->getLang('oauthpdo login failed'),0);
                        $this->cleanLogout();
                        $authenticated = false;
                    } else {
                        // first time here
                        return $this->relogin($servicename);
                    }
                }

                $this->cleanLogout();
                $authenticated = false; // something went wrong during oAuth login
            } elseif (isset($_COOKIE[DOKU_COOKIE])) {
                global $INPUT;
                //try cookie
                list($cookieuser, $cookiesticky, $auth, $servicename) = explode('|', $_COOKIE[DOKU_COOKIE]);
                $cookieuser = base64_decode($cookieuser, true);
                $auth = base64_decode($auth, true);
                $servicename = base64_decode($servicename, true);
                if ($auth === 'oauthpdo') {
                    return $this->relogin($servicename);
                }
            }
        }

        if (is_null($authenticated)) {
            // do the "normal" plain auth login via form
            $authenticated = auth_login($user, $pass, $sticky);
        }
                if (isset($_SESSION[DOKU_COOKIE]['oauthpdo-inprogress']) &&
                    isset($_SESSION[DOKU_COOKIE]['oauthpdo-inprogress']['addNew']) &&
                    $_SESSION[DOKU_COOKIE]['oauthpdo-inprogress']['addNew']
                ) {
                    $_SESSION[DOKU_COOKIE]['oauthpdo-done']['do'] = 'profile';
                    $addNewLogin = TRUE;
                } else {
                    // Check for oauthremove flag
                    $servicename = $INPUT->str('oauthremove');
                    if ($servicename) {
                        $hlp     = plugin_load('helper', 'oauthpdo');
                        $service     = $hlp->loadService($servicename);
                        if (!is_null($service)) {
                            // remove the oauth entry in-place before doing any other action
                            $_SESSION[DOKU_COOKIE]['oauthpdo-done']['do'] = 'profile';
                            return $this->oauthRemove($servicename, $INPUT->str('email'));
                        }
                    }
                    return TRUE;
                }

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
                    msg(sprintf($this->getLang('oauthRemoveSuccessful'), $serviceName, $email), 1);
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
        error_log('$this->isSessionValid()');
        $hlp     = plugin_load('helper', 'oauthpdo');
        if ($hlp->validBrowserID($session)) {
            if (!$hlp->isSessionTimedOut($session)) {
                return true;
            } elseif (!($hlp->isGETRequest() && $hlp->isDokuPHP())) {
                // only force a recheck on a timed-out session during a GET request on the main script doku.php
                return true;
            }
        }
        error_log('$this->isSessionValid() === FALSE');
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
        error_log('$this->processLogin(): addNew' . $addNew);
        $uinfo = $service->getUser();
        $ok = $this->processUser($uinfo, $servicename, $addNew);
        if ($ok) {
            if ($addNew) {
                global $USERINFO;
                $this->updateUserSessionInfo($USERINFO);
                $_SESSION[DOKU_COOKIE]['oauthpdo-done']['msg'] = sprintf($this->getLang('oauthAddSuccessful'), $servicename, $uinfo['mail']);
                $_SESSION[DOKU_COOKIE]['oauthpdo-done']['msgLvl'] = 1;
            } else {
                $this->setUserSession($uinfo, $servicename);
                $this->setUserCookie($uinfo['user'], $sticky, $servicename);
            }
        }
        if (!$addNew && !$ok) {
            return false;
        }
        if(isset($page)) {
            if(!empty($params['id'])) unset($params['id']);
            send_redirect(wl($page, $params, false, '&'));
        }
        return $ok;
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
        error_log('$this->processUser(): addnew: ' . $addNew);
        $actionDesc = $addNew ? "link your account" : "log you in";
        if(!$uinfo['name']) $uinfo['name'] = $uinfo['user'];

        if(!$uinfo['user'] || !$uinfo['mail']) {
            msg("$servicename did not provide the needed user info. Can't " . $actionDesc, -1);
            return false;
        }

        // see if the user is known already
        if ($addNew) {
            global $USERINFO;
            $user = $this->getUserByEmail($uinfo['mail'], $servicename);
            error_log('$user: ' . $user);
            if ($user) {
                if ($user !== $_SESSION[DOKU_COOKIE]['auth']['user']) {
                    msg(sprintf($this->getLang('serviceAlreadyLinked'), $servicename, $uinfo['mail']), -1);
                } else {
                    msg(sprintf($this->getLang('serviceAlreadyLinkedSameUser'), $servicename, $uinfo['mail']), 0);
                }
                return FALSE;
            }
            $sql = $this->getConf('add-linked-emails');
            $mail = strtolower($uinfo['mail']);
            error_log(json_encode($USERINFO, JSON_PRETTY_PRINT));
            $result = $this->_query($sql, array_merge($USERINFO, array(':email' => $mail, ':service' => strtolower($servicename))));
            if (!$result) {
                msg($this->getLang('cannotAddLinkedEmail'), -1);
                return false;
            } else {
                $USERINFO['linkedAccounts'][strtolower($servicename)] []= $mail;
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
                    msg('Something went wrong creating your user account. please try again later.', -1);
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
            $result = $this->_query($sql, array(':mail' => $mail, ':service' => strtolower($servicename)));
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
