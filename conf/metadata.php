<?php
/**
 * Options for the DokuWiki Plugin for Magento (Auth Component)
 *
 * @license GPL v3 http://www.gnu.org
 * @author Z3 Development <z3-dev@gfnews.net>
 */

$meta['databaseDSN']          = array( 'string' );
$meta['databaseUser']         = array( 'string' );
$meta['databasePassword']     = array( 'password' );
$meta['debugDatabase']        = array( 'onoff' );

$meta['includeCustomers']     = array( 'onoff' );
$meta['includeGroups']        = array( 'onoff' );
$meta['includeDefaultGroup']  = array( 'onoff' );
$meta['userGroups']           = array( 'string' );

$meta['includeAdmins'] = array( 'onoff' );
$meta['includeRoles']  = array( 'onoff' );
$meta['adminGroups']   = array( 'string' );

