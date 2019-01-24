<?php
/**
 * DokuWiki Plugin oauthpdo (Action Component)
 *
 * @license GPL 2 http://www.gnu.org/licenses/gpl-2.0.html
 * @author  Andreas Gohr <andi@splitbrain.org>
 */

// must be run within Dokuwiki
if(!defined('DOKU_INC')) die();

class action_plugin_oauthpdo extends DokuWiki_Action_Plugin {

    /**
     * Registers a callback function for a given event
     *
     * @param Doku_Event_Handler $controller DokuWiki's event controller object
     * @return void
     */
    public function register(Doku_Event_Handler $controller) {
        global $conf;
        error_log('action::register');

        if($conf['authtype'] != 'oauthpdo') return;

        $conf['profileconfirm'] = false; // password confirmation doesn't work with oauthpdo only users

        $controller->register_hook('DOKUWIKI_STARTED', 'BEFORE', $this, 'handle_start');
        $controller->register_hook('HTML_LOGINFORM_OUTPUT', 'BEFORE', $this, 'handle_loginform');
        $controller->register_hook('HTML_UPDATEPROFILEFORM_OUTPUT', 'BEFORE', $this, 'handle_profileform');
        $controller->register_hook('AUTH_USER_CHANGE', 'BEFORE', $this, 'handle_usermod');
        $controller->register_hook('ACTION_ACT_PREPROCESS', 'BEFORE', $this, 'handle_dologin');
    }

    /**
     * Start an oAuth login or restore  environment after successful login
     *
     * @param Doku_Event $event  event object by reference
     * @param mixed      $param  [the parameters passed as fifth argument to register_hook() when this
     *                           handler was registered]
     * @return void
     */
    public function handle_start(Doku_Event &$event, $param) {

        error_log('action::handle_start');

        if (isset($_SESSION[DOKU_COOKIE]['oauthpdo-done']['do']) || !empty($_SESSION[DOKU_COOKIE]['oauthpdo-done']['rev'])){
            $this->restoreSessionEnvironment();
            return;
        }

        $this->startOAuthLogin();
    }

    private function startOAuthLogin() {
        global $INPUT, $ID;

        error_log('action::startOAuthLogin');

        /** @var helper_plugin_oauthpdo $hlp */
        $hlp         = plugin_load('helper', 'oauthpdo');
        $servicename = $INPUT->str('oauthlogin');
        $service     = $hlp->loadService($servicename);
        if(is_null($service)) {
            // Not an actual login service
            // However, it is still possible the user is trying to link a new
            // oauth account
            $notInitLogin = true;
            $servicename = $INPUT->str('oauthadd');
            $service     = $hlp->loadService($servicename);
            if (is_null($service)) {
                return;
            }
        }

        // remember service in session
        session_start();
        $_SESSION[DOKU_COOKIE]['oauthpdo-inprogress']['service'] = $servicename;
        $_SESSION[DOKU_COOKIE]['oauthpdo-inprogress']['id']      = $ID;
        $_SESSION[DOKU_COOKIE]['oauthpdo-inprogress']['addNew']  = $notInitLogin;
        session_write_close();

        $service->login();
    }

    private function restoreSessionEnvironment() {
        global $INPUT, $ACT, $TEXT, $PRE, $SUF, $SUM, $RANGE, $DATE_AT, $REV;
        error_log('action::restoreSessionEnv');

        $ACT = $_SESSION[DOKU_COOKIE]['oauthpdo-done']['do'];
        $_REQUEST = $_SESSION[DOKU_COOKIE]['oauthpdo-done']['$_REQUEST'];

        $REV   = $INPUT->int('rev');
        $DATE_AT = $INPUT->str('at');
        $RANGE = $INPUT->str('range');
        if($INPUT->post->has('wikitext')) {
            $TEXT = cleanText($INPUT->post->str('wikitext'));
        }
        $PRE = cleanText(substr($INPUT->post->str('prefix'), 0, -1));
        $SUF = cleanText($INPUT->post->str('suffix'));
        $SUM = $INPUT->post->str('summary');

        unset($_SESSION[DOKU_COOKIE]['oauthpdo-done']);
    }

    /**
     * Save groups for all the services a user has enabled
     *
     * @param Doku_Event $event  event object by reference
     * @param mixed      $param  [the parameters passed as fifth argument to register_hook() when this
     *                           handler was registered]
     * @return void
     */
    public function handle_usermod(Doku_Event &$event, $param) {
        global $ACT;
        global $USERINFO;
        global $auth;
        global $INPUT;

        error_log('action::handle_usermod');

        if($event->data['type'] != 'modify') return;
        if($ACT != 'profile') return;

        // we want to modify the user's groups
        $groups = $USERINFO['grps']; //current groups
        if(isset($event->data['params'][1]['grps'])) {
            // something already defined new groups
            $groups = $event->data['params'][1]['grps'];
        }

        /** @var helper_plugin_oauthpdo $hlp */
        $hlp = plugin_load('helper', 'oauthpdo');

        // get enabled and configured services
        $enabled  = $INPUT->arr('oauthpdo_group');
        $services = $hlp->listServices();
        $services = array_map(array($auth, 'cleanGroup'), $services);

        // add all enabled services as group, remove all disabled services
        foreach($services as $service) {
            if(isset($enabled[$service])) {
                $groups[] = $service;
            } else {
                $idx = array_search($service, $groups);
                if($idx !== false) unset($groups[$idx]);
            }
        }
        $groups = array_unique($groups);

        // add new group array to event data
        $event->data['params'][1]['grps'] = $groups;

    }

    /**
     * Add service selection to user profile
     *
     * @param Doku_Event $event  event object by reference
     * @param mixed      $param  [the parameters passed as fifth argument to register_hook() when this
     *                           handler was registered]
     * @return void
     */
    public function handle_profileform(Doku_Event &$event, $param) {
        global $USERINFO;
        /** @var auth_plugin_authplain $auth */
        global $auth;

        error_log('action::handle_profileform');

        /** @var helper_plugin_oauthpdo $hlp */
        $hlp = plugin_load('helper', 'oauthpdo');

        /** @var Doku_Form $form */
        $form =& $event->data;
        $pos  = $form->findElementByAttribute('type', 'submit');

        $services = $hlp->listServices();
        if(!$services) return;

        $form->insertElement($pos, form_closefieldset());
        $form->insertElement(++$pos, form_openfieldset(array('_legend' => $this->getLang('loginwith'), 'class' => 'plugin_oauthpdo')));
        foreach($services as $service) {
            if ($singleService == '') {

                foreach($hlp->listServices() as $service) {
                    if ($isset($USERINFO['linkedAccounts'][strtolower($service)])) {
                        foreach($USERINFO['linkedAccounts'][strtolower($service)] as $email) {
                            $html .= $email . '<br>';
                        }
                    }
                    $html .= $this->service_html($service);
                }
                if(!$html) return;

            }else{
                if (in_array($singleService, $enabledServices, true) === false) {
                    msg($this->getLang('wrongConfig'),-1);
                    return;
                }
                $form->_content = array();
                $html = $this->service_html($singleService);

            }
            $elem  = form_makeCheckboxField(
                'oauthpdo_group['.$group.']',
                1, $service, '', 'simple',
                array(
                    'checked' => (in_array($group, $USERINFO['grps'])) ? 'checked' : ''
                )
            );

            $form->insertElement(++$pos, $elem);
        }
        $form->insertElement(++$pos, form_closefieldset());
        $form->insertElement(++$pos, form_openfieldset(array()));
    }

    /**
     * Add the oAuth login links
     *
     * @param Doku_Event $event  event object by reference
     * @param mixed      $param  [the parameters passed as fifth argument to register_hook() when this
     *                           handler was registered]
     * @return void
     */
    public function handle_loginform(Doku_Event &$event, $param) {
        global $conf;

        error_log('action::handle_loginform');

        /** @var helper_plugin_oauthpdo $hlp */
        $hlp = plugin_load('helper', 'oauthpdo');
        $singleService = $this->getConf('singleService');
        $enabledServices = $hlp->listServices();

        /** @var Doku_Form $form */
        $form =& $event->data;
        $html = '';

        $validDomains = $hlp->getValidDomains();

        if (count($validDomains) > 0) {
            $html .= sprintf($this->getLang('eMailRestricted'), join(', ', $validDomains));
        }

        if ($singleService == '') {

            foreach($hlp->listServices() as $service) {
                $html .= $this->service_html($service);
            }
            if(!$html) return;

        }else{
            if (in_array($singleService, $enabledServices, true) === false) {
                msg($this->getLang('wrongConfig'),-1);
                return;
            }
            $form->_content = array();
            $html = $this->service_html($singleService);

        }
        $form->_content[] = form_openfieldset(array('_legend' => '', 'class' => 'plugin_oauthpdo'));
        $form->_content[] = $html;
        $form->_content[] = form_closefieldset();
    }

    function service_html ($service){
        global $ID;
        $html = '';
        $html .= '<a href="' . wl($ID, array('oauthlogin' => $service)) . '" class="plugin_oauthpdo_' . $service . '">';
        $html .= '<div>' . $this->getLang('loginButton') . $service . '</div>';
        $html .= '</a> ';
        return $html;
    }

    function link_service_html ($service){
        global $ID;
        $html = '';
        $html .= '<a href="' . wl($ID, array('oauthadd' => $service, 'do' => 'profile')) . '" class="plugin_oauthpdo_' . $service . '">';
        $html .= '<div>' . $this->getLang('addLoginButton') . $service . '</div>';
        $html .= '</a> ';
        return $html;
    }

    public function handle_dologin(Doku_Event &$event, $param) {
        global $lang;
        global $ID;

        error_log('action::handle_dologin');

        $singleService = $this->getConf('singleService');
        if ($singleService == '') return true;

        $lang['btn_login'] = $this->getLang('loginButton') . $singleService;

        if($event->data != 'login') return true;



        /** @var helper_plugin_oauthpdo $hlp */
        $hlp = plugin_load('helper', 'oauthpdo');
        $enabledServices = $hlp->listServices();
        if (in_array($singleService, $enabledServices, true) === false) {
            msg($this->getLang('wrongConfig'),-1);
            return false;
        }

        $url = wl($ID, array('oauthlogin' => $singleService), true, '&');
        send_redirect($url);
    }

}
// vim:ts=4:sw=4:et:
