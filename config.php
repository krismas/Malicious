<?php
/*
 * Paths & limit
 *
 * @info Path are relative to Malicious core
 */
define('MCS_ROOT'   , dirname(__FILE__).'/.');     // Directory to scan
define('MCS_LOGS'   , dirname(__FILE__).'/logs');  // Where to save logs
define('MCS_NOLIMIT', true);                       // Disable memory limit & timeout

/*
 * Authorizations
 */
define('MCS_SECRET', '0617c3052b0360c3aa184986aede9053');

/*
 * Some basics "Check configurations"
 */
define('MCS_PLUGINS'  , 'readable');
define('MCS_PLUGINS_1', 'readable,updated');

/*
 * Some basics "Report configurations"
 */
define('MCS_REPORTS'  , 'echo');
define('MCS_REPORTS_1', 'echo,log');
