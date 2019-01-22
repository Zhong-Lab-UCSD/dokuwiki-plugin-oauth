<?php
/**
 * english language file for oauthpdo plugin
 *
 * @author Andreas Gohr <andi@splitbrain.org>
 */


$lang['info']            = 'Redirect URI to use when configuring the applications';
$lang['custom-redirectURI'] = 'Use the following custom redirect URI';
$lang['auth0-key']       = 'The Client ID of your registered <a href="https://manage.auth0.com/#/applications">Auth0 application</a>';
$lang['auth0-secret']    = 'The Client Secret of your registered <a href="https://manage.auth0.com/#/applications">Auth0 application</a>';
$lang['auth0-domain']    = 'The Domain of your registered <a href="https://manage.auth0.com/#/applications">Auth0 account</a>';
$lang['facebook-key']    = 'The App ID of your registered <a href="https://developers.facebook.com/apps">Facebook application</a>';
$lang['facebook-secret'] = 'The App Secret of your registered <a href="https://developers.facebook.com/apps">Facebook application</a>';
$lang['github-key']      = 'The Client ID of your registered <a href="https://github.com/settings/applications">Github application</a>';
$lang['github-secret']   = 'The Client Secret of your registered <a href="https://github.com/settings/applications">Github application</a>';
$lang['google-key']      = 'The Client ID of your registered <a href="https://console.developers.google.com/project">Google Project</a> (see Credentials Screen)';
$lang['google-secret']   = 'The Client Secret of your registered <a href="https://console.developers.google.com/project">Google Project</a> (see Credentials Screen)';
$lang['dataporten-key']  = 'The Client ID of your registered <a href="https://dashboard.dataporten.no">Dataporten application</a>';
$lang['dataporten-secret'] = 'The Client Secret of your registered <a href="https://dashboard.dataporten.no">Dataporten application</a>';
$lang['keycloak-key']      = 'The resource id of your Keycloak application.';
$lang['keycloak-secret']   = 'The Secret of your Keycloak Application.';
$lang['keycloak-authurl']  = 'The authorization endpoint URL of your Keycloak setup.';
$lang['keycloak-tokenurl'] = 'The access token endpoint URL of your Keycloak setup.';
$lang['keycloak-userinfourl'] = 'The userinfo endpoint URL of your Keycloak setup.';
$lang['mailRestriction']   = "Limit authentification to users from this domain (optional, must start with an <code>@</code>)";
$lang['yahoo-key']       = 'The Consumer Key of your registered <a href="https://developer.apps.yahoo.com/dashboard/createKey.html">Yahoo Application</a>';
$lang['yahoo-secret']    = 'The Consumer Secret of your registered <a href="https://developer.apps.yahoo.com/dashboard/createKey.html">Yahoo Application</a>';
$lang['doorkeeper-key']      = '(Example) The Application ID of your registered Doorkeeper Application.';
$lang['doorkeeper-secret']   = '(Example) The Secret of your registered Doorkeeper Application.';
$lang['doorkeeper-authurl']  = '(Example) The authorization endpoint URL of your Doorkeeper setup.';
$lang['doorkeeper-tokenurl'] = '(Example) The access token endpoint URL of your Doorkeeper setup.';
$lang['singleService']            = 'Login with single oAuth service only (disables local logins!)';
$lang['singleService_o_'] = 'Allow all services';
$lang['serviceOrder']            = 'The order of the services, separated by comma. Unlisted but supported services will be appended to the end of the list.';

$lang['debug']              = 'Print out detailed error messages. Should be disabled after setup.';
$lang['dsn']                = 'The DSN to connect to the database.';
$lang['user']               = 'The user for the above database connection (empty for sqlite)';
$lang['pass']               = 'The password for the above database connection (empty for sqlite)';
$lang['select-user']        = 'SQL Statement to select the data of a single user';
$lang['select-user-from-email-with-service']        = 'SQL Statement to select the user name with email from a given service';
$lang['select-user-from-email']        = 'SQL Statement to select the user name with email from any given service';
$lang['select-user-groups'] = 'SQL Statement to select all groups of a single user';
$lang['select-groups']      = 'SQL Statement to select all available groups';
$lang['insert-user']        = 'SQL Statement to insert a new user into the database';
$lang['delete-user']        = 'SQL Statement to remove a single user from the database';
$lang['list-users']         = 'SQL Statement to list users matching a filter';
$lang['count-users']        = 'SQL Statement to count users matching a filter';
$lang['update-user-info']   = 'SQL Statement to update the full name and email address of a single user';
$lang['update-user-login']  = 'SQL Statement to update the login name of a single user';
$lang['update-user-pass']   = 'SQL Statement to update the password of a single user';
$lang['insert-group']       = 'SQL Statement to insert a new group into the database';
$lang['join-group']         = 'SQL Statement to add a user to an existing group';
$lang['leave-group']        = 'SQL Statement to remove a user from a group';
$lang['check-pass']         = 'SQL Statement to check the password for a user. Can be left empty if password info is fetched in select-user.';
