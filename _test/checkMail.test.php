<?php
/**
 * General tests for the oauthpdo plugin
 *
 * @group plugin_oauthpdo
 * @group plugins
 */
class checkMail_plugin_oauthpdo_test extends DokuWikiTest {

    protected $pluginsEnabled = array('oauthpdo');

    public function test_checkMail_twoDomains() {

        global $conf;
        $conf['plugin']['oauthpdo']['mailRestriction'] = '@foo.org,@example.com';

        /** @var helper_plugin_oauthpdo $hlp */
        $hlp     = plugin_load('helper', 'oauthpdo');

        $testmail = "bar@foo.org";
        $this->assertTrue($hlp->checkMail($testmail),$testmail);
        $testmail = "bar@example.com";
        $this->assertTrue($hlp->checkMail($testmail), $testmail);
        $testmail = "bar@bar.org";
        $this->assertFalse($hlp->checkMail($testmail), $testmail);
    }

    public function test_checkMail_oneDomains() {

        global $conf;
        $conf['plugin']['oauthpdo']['mailRestriction'] = '@foo.org';

        /** @var helper_plugin_oauthpdo $hlp */
        $hlp     = plugin_load('helper', 'oauthpdo');

        $testmail = "bar@foo.org";
        $this->assertTrue($hlp->checkMail($testmail),$testmail);
        $testmail = "bar@example.com";
        $this->assertFalse($hlp->checkMail($testmail), $testmail);
        $testmail = "bar@bar.org";
        $this->assertFalse($hlp->checkMail($testmail), $testmail);
    }

}
