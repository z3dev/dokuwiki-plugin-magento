<?php
/**
 * Default Settings for the DokuWiki Plugin for Magento (Auth Component)
 *
 * @license GPL v3 http://www.gnu.org
 * @author Z3 Development <z3-dev@gfnews.net>
 */

$conf['databaseDSN']      = 'mysql:host=localhost;dbname=magento-db';
$conf['databaseUser']     = 'dokuwiki';
$conf['databasePassword'] = 'password';
$conf['debugDatabase']    = '1';

$conf['includeCustomers']    = '1';
$conf['includeGroups']       = '1';
$conf['includeDefaultGroup'] = '1';
$conf['userGroups']          = '';

$conf['includeAdmins'] = '1';
$conf['includeRoles']  = '1';
$conf['adminGroups']   = 'admin';

