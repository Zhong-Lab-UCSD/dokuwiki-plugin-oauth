<?php
/**
 * Options for the oauthpdo plugin
 *
 * @author Andreas Gohr <andi@splitbrain.org>
 */

class setting_plugin_oauthpdo extends setting {

    function update($input) {
        return true;
    }

    public function html(&$plugin, $echo = false) {
        /** @var helper_plugin_oauthpdo $hlp */
        $hlp = plugin_load('helper', 'oauthpdo');

        $key   = htmlspecialchars($this->_key);
        $value = '<code>'.$hlp->redirectURI().'</code>';

        $label = '<label for="config___'.$key.'">'.$this->prompt($plugin).'</label>';
        $input = '<div>'.$value.'</div>';
        return array($label, $input);
    }

}

$meta['info']                = array('plugin_oauthpdo');
$meta['auth0-key']           = array('string');
$meta['auth0-secret']        = array('string');
$meta['auth0-domain']        = array('string');
$meta['custom-redirectURI']  = array('string','_caution' => 'warning');
$meta['facebook-key']        = array('string');
$meta['facebook-secret']     = array('string');
$meta['github-key']          = array('string');
$meta['github-secret']       = array('string');
$meta['google-key']          = array('string');
$meta['google-secret']       = array('string');
$meta['dataporten-key']      = array('string');
$meta['dataporten-secret']   = array('string');
$meta['keycloak-key']        = array('string');
$meta['keycloak-secret']     = array('string');
$meta['keycloak-authurl']    = array('string');
$meta['keycloak-tokenurl']   = array('string');
$meta['keycloak-userinfourl'] = array('string');
$meta['yahoo-key']           = array('string');
$meta['yahoo-secret']        = array('string');
$meta['doorkeeper-key']      = array('string');
$meta['doorkeeper-secret']   = array('string');
$meta['doorkeeper-authurl']  = array('string');
$meta['doorkeeper-tokenurl'] = array('string');
$meta['mailRestriction']     = array('string','_pattern' => '!^(@[^,@]+(\.[^,@]+)+(,|$))*$!'); // https://regex101.com/r/mG4aL5/3
$meta['singleService']       = array('multichoice',
                                     '_choices' => array(
                                         '',
                                         'Auth0',
                                         'Google',
                                         'Dataporten',
                                         'Facebook',
                                         'Github',
                                         'Yahoo',
                                         'Doorkeeper',
                                         'Keycloak'));
$meta['serviceOrder'] = array('string');

/**
 * Options for the authpdo plugin
 *
 * @author Andreas Gohr <andi@splitbrain.org>
 */
$meta['debug']              = array('onoff', '_caution' => 'security');
$meta['dsn']                = array('string', '_caution' => 'danger');
$meta['user']               = array('string', '_caution' => 'danger');
$meta['pass']               = array('password', '_caution' => 'danger', '_code' => 'base64');
$meta['select-user']        = array('', '_caution' => 'danger');
$meta['select-user-from-email-with-service']    = array('', '_caution' => 'danger');
$meta['select-user-from-email']                 = array('', '_caution' => 'danger');
$meta['get-user-linked-emails']                 = array('', '_caution' => 'danger');
$meta['add-linked-emails']                      = array('', '_caution' => 'danger');
$meta['remove-linked-emails']                   = array('', '_caution' => 'danger');
$meta['update-login-time']                      = array('', '_caution' => 'danger');
$meta['update-login-time-oauth']                = array('', '_caution' => 'danger');
$meta['check-pass']         = array('', '_caution' => 'danger');
$meta['select-user-groups'] = array('', '_caution' => 'danger');
$meta['select-groups']      = array('', '_caution' => 'danger');
$meta['insert-user']        = array('', '_caution' => 'danger');
$meta['delete-user']        = array('', '_caution' => 'danger');
$meta['list-users']         = array('', '_caution' => 'danger');
$meta['count-users']        = array('', '_caution' => 'danger');
$meta['update-user-info']   = array('', '_caution' => 'danger');
$meta['update-user-login']  = array('', '_caution' => 'danger');
$meta['update-user-pass']   = array('', '_caution' => 'danger');
$meta['insert-group']       = array('', '_caution' => 'danger');
$meta['join-group']         = array('', '_caution' => 'danger');
$meta['leave-group']        = array('', '_caution' => 'danger');
