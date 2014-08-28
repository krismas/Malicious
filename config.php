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
 * Some basics "Check configurations"
 */
define('MCS_PLUGINS'  , 'readable,eval');
define('MCS_PLUGINS_1', 'readable,eval,empty,updated,writable,big,hidden');

/*
 * Some basics "Report configurations"
 */
define('MCS_REPORTS'  , 'echo,log');
define('MCS_REPORTS_1', 'echo,log');
