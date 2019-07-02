<?php
/**
 * Default settings for the oauthpdo plugin
 *
 * @author Andreas Gohr <andi@splitbrain.org>
 */

$conf['auth0-key']           = '';
$conf['auth0-secret']        = '';
$conf['auth0-domain']        = '';
$conf['custom-redirectURI']  = '';
$conf['facebook-key']        = '';
$conf['facebook-secret']     = '';
$conf['github-key']          = '';
$conf['github-secret']       = '';
$conf['google-key']          = '';
$conf['google-secret']       = '';
$conf['dataporten-key']      = '';
$conf['dataporten-secret']   = '';
$conf['keycloak-key']        = '';
$conf['keycloak-secret']     = '';
$conf['keycloak-authurl']    = 'https://keycloak.example.com/auth/realms/{realm}/protocol/openid-connect/auth';
$conf['keycloak-tokenurl']   = 'https://keycloak.example.com/auth/realms/{realm}/protocol/openid-connect/token';
$conf['keycloak-userinfourl'] = 'https://keycloak.example.com/auth/realms/{realm}/protocol/openid-connect/userinfo';
$conf['yahoo-key']           = '';
$conf['yahoo-secret']        = '';
$conf['doorkeeper-key']      = '';
$conf['doorkeeper-secret']   = '';
$conf['doorkeeper-authurl']  = 'https://doorkeeper-provider.herokuapp.com/oauthpdo/authorize';
$conf['doorkeeper-tokenurl'] = 'https://doorkeeper-provider.herokuapp.com/oauthpdo/token';
$conf['mailRestriction']     = '';
$conf['singleService']       = '';
$conf['serviceOrder']       = '';

/**
 * Default settings for the authpdo plugin
 *
 * @author Andreas Gohr <andi@splitbrain.org>
 */
$conf['debug'] = 0;
$conf['dsn'] = '';
$conf['user'] = '';
$conf['pass'] = '';
/**
 * statement to select a single user identified by its login name
 *
 * input: :user
 * return: user, name, mail, (clear|hash), [uid], [*]
 */
$conf['select-user'] = '';
/**
 * statement to select a single user identified by email and service name
 *
 * input: :mail, :service
 * return: user
 */
$conf['select-user-from-email-with-service'] = '';
/**
 * statement to update the last login timestamp when using user name
 *
 * input: :user
 */
$conf['update-login-time'] = '';
/**
 * statement to update the last login timestamp when using oauth
 *
 * input: :uid, :email, :service
 */
$conf['update-login-time-oauth'] = '';
/**
 * statement to select a single user identified by email
 *
 * input: :mail
 * return: user
 */
$conf['select-user-from-email'] = '';
/**
 * statement to select all linked emails of the user
 *
 * input: :user, [:uid]
 * return: service, email
 */
$conf['get-user-linked-emails'] = '';
/**
 * statement to link a new email account for the user
 *
 * input: :user, [:uid], :service, :email
 */
$conf['add-linked-emails'] = '';
/**
 * statement to remove a linked email account for the user
 *
 * input: :user, [:uid], :service, :email
 */
$conf['remove-linked-emails'] = '';
/**
 * statement to check the password in SQL, optional when above returned clear or hash
 *
 * input: :user, :clear, :hash, [uid], [*]
 * return: *
 */
$conf['check-pass'] = '';
/**
 * statement to select a single user identified by its login name
 *
 * input: :user, [uid]
 * return: group
 */
$conf['select-user-groups'] = '';
/**
 * Select all the existing group names
 *
 * return: group, [gid], [*]
 */
$conf['select-groups'] = '';
/**
 * Create a new user
 *
 * input: :user, :name, :mail, (:clear|:hash)
 */
$conf['insert-user'] = '';
/**
 * Remove a user
 *
 * input: :user, [:uid], [*]
 */
$conf['delete-user'] = '';
/**
 * list user names matching the given criteria
 *
 * Make sure the list is distinct and sorted by user name. Apply the given limit and offset
 *
 * input: :user, :name, :mail, :group, :start, :end, :limit
 * out: user
 */
$conf['list-users'] = '';
/**
 * count user names matching the given criteria
 *
 * Make sure the counted list is distinct
 *
 * input: :user, :name, :mail, :group
 * out: count
 */
$conf['count-users'] = '';
/**
 * Update user data (except password and user name)
 *
 * input: :user, :name, :mail, [:uid], [*]
 */
$conf['update-user-info'] = '';
/**
 * Update user name aka login
 *
 * input: :user, :newlogin, [:uid], [*]
 */
$conf['update-user-login'] = '';
/**
 * Update user password
 *
 * input: :user, :clear, :hash, [:uid], [*]
 */
$conf['update-user-pass'] = '';
/**
 * Create a new group
 *
 * input: :group
 */
$conf['insert-group'] = '';
/**
 * Make user join group
 *
 * input: :user, [:uid], group, [:gid], [*]
 */
$conf['join-group'] = '';
/**
 * Make user leave group
 *
 * input: :user, [:uid], group, [:gid], [*]
 */
$conf['leave-group'] = '';