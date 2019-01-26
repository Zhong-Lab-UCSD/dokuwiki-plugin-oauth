<?php
/**
 * English language file for oauthpdo plugin
 *
 * @author Andreas Gohr <andi@splitbrain.org>
 */

$lang['emailduplicate'] = 'This email is already associated with another user.';
$lang['loginwith']      = 'Login with other Services:';
$lang['loginWithDesc']      = 'You may link multiple accounts from supported services in order to login with those accounts.';
$lang['linkedServiceGroup']      = 'Linked %s account(s)';
$lang['unlink']      = 'Unlink this account';
$lang['authnotenabled'] = 'The account associated with your email address has not enabled logging in with %s. Please login by other means and enable it in your profile.';
$lang['wrongConfig'] = 'The oAuth plugin has been malconfigured. Defaulting to local authentication only. Please contact your wiki administrator.';
$lang['loginButton'] = 'Sign in with ';//... i.e. Google (on SingleAuth)
$lang['addLoginButton'] = 'Link another %s account';//... i.e. Google (on SingleAuth)
$lang['rejectedEMail'] = 'Invalid eMail-Account used. Only email accounts from the following domain(s) are allowed: %s!';
$lang['eMailRestricted'] = '<p id="oauthpdo_email_restricted">Only email accounts from the following domain(s) are allowed: %s</p>';
$lang['cannotAddLinkedEmail'] = 'Cannot link to a new email account.';
$lang['addUser not possible'] = 'This account is not linked to any wiki accounts.';
$lang['serviceAlreadyLinked'] = 'This %s account (%s) has already been linked to another account. Please let us know if you think this should not happen.';
$lang['serviceAlreadyLinkedSameUser'] = 'You have already linked this %s account (%s) to your profile.';
$lang['oauthRemoveSuccessful'] = 'The %s account (%s) has been unlinked from your profile.';
$lang['oauthAddSuccessful'] = 'The %s account (%s) has been linked to your profile. You may login with this account in the future.';
$lang['wrongEmailToUnlink'] = 'Cannot unlink account.';
$lang['oauthpdo login failed'] = 'Your (re)login has failed.';
