<?php
/**
 * Malicious - Configuration
 *
 * @copyright Ackwa.fr - 2014
 *
 * Paths & limit
 *
 * @info Path are relative to Malicious core
 */
define('MCS_ROOT'   , dirname(__FILE__).'/..');    // Directory to scan
define('MCS_LOGS'   , dirname(__FILE__).'/logs');  // Where to save logs
define('MCS_NOLIMIT', true);                       // Disable memory limit & timeout

/*
 * Authorizations
 */
define('MCS_SECRET', 'mysecretkey');

/*
 * Notification
 */
define('MCS_EMAIL', 'info@ackwa.fr');
define('MCS_SITE' , 'Ackwa');

/*
 * Some basics "Check configurations"
 */
define('MCS_PLUGINS'  , 'readable,eval,exec');
define('MCS_PLUGINS_1', 'updated');
define('MCS_PLUGINS_2', 'readable,eval,exec,empty,updated,writable,big,hidden');

/*
 * Some basics "Report configurations"
 */
define('MCS_REPORTS'  , 'echo,log');
define('MCS_REPORTS_1', 'mail,log');
