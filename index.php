<?php
/**
 * Malicious
 *
 * A simple, lightweight framework to detect potential suspicious/malicious PHP Code and few other
 * commons sources of problems. Fully extensible with plugins (Check & Report) support...
 *
 * @copyright Ackwa.fr - 2014
 *
 * Load configuration file
 */
require(dirname(__FILE__).'/config.php');

/**
 * Some local definition
 */
define('MCS_VERSION', '0.1-beta');
define('MCS_START'  , _now());
register_shutdown_function('_stop');
spl_autoload_register('autoloadPlugins');

/**
 * Initialization
 */
$aOptions = getopt("c:r:s:");
$aOptions = (is_array($aOptions) ? $aOptions : $_GET);
$iCheck   = (isset($aOptions['c']) ? $aOptions['c'] :  0) + 0;
$iReport  = (isset($aOptions['r']) ? $aOptions['r'] :  0) + 0;
$sSecret  = (isset($aOptions['s']) ? $aOptions['s'] : '');

/*
 * Log some informations
 */
$aPUID = posix_getpwuid(posix_geteuid());
$aPGID = posix_getgrgid(posix_getegid());
_log(str_repeat('-', 80));
_log('Malicious '.MCS_VERSION.' started... PHP '.phpversion().' / '.php_sapi_name().' on '.(isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : 'localhost').' for '.(isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '???'));
_log('Process is owned by '.$aPUID['name'].' ('.$aPUID['uid'].') / '.$aPGID['name'].' ('.$aPGID['gid'].') with umask '.sprintf('%04o', umask()).' running in '.realpath(getcwd()));

/*
 * Check Authorisation
 */
if (MCS_SECRET == $sSecret) {
    /*
     * Try to avoid memory & timeout errors (i.e in foreachloop)
     */
    if (MCS_NOLIMIT) {
        if (ini_get('safe_mode')) {
            _log('In safe mode we can\'t change the maximum execution time. Timeout may occur...');
        }
        else {
            ini_set('memory_limit', '-1');
            @set_time_limit(0);
        }
    }

    /*
     * Get "check plugins" configuration
     */
    if ($iCheck && defined('MCS_PLUGINS_'.$iCheck)) {
        $sPlugins = constant('MCS_PLUGINS_'.$iCheck);
    }
    else {
        $sPlugins = MCS_PLUGINS;
    }

    /*
     * Get "report plugins" configuration
     */
    if ($iReport && defined('MCS_REPORTS_'.$iReport)) {
        $sReports = constant('MCS_REPORTS_'.$iReport);
    }
    else {
        $sReports = MCS_REPORTS;
    }

    /*
     * Load "Check plugins"...
     */
    $lChecks = loadPlugins($sPlugins, 'Check');

    /*
     * Start scanner...
     */
    _log('Scan '.realpath(MCS_ROOT).' directory with : '.implode(', ', array_keys($lChecks)).' plugins.');
    scan(MCS_ROOT, $lChecks);

    /*
     * Load and execute "Report plugins"...
     */
    $lReports = loadPlugins($sReports, 'Report');
    foreach($lReports as $oO) $oO->report($lChecks);
}
else {
    _log('Unauthorized client request: ['.$sSecret.']');
}
define('MCS_STOP', _now());

/**
 * Recursive Directory Scan & file check function
 *
 * @param string $sDir      Directory to scan
 * @param array  $aPlugins  Plugins to execute
 */
function scan($sDir, $aPlugins = array()) {
    if (is_readable($sDir)) {
        $lFiles = scandir(realpath($sDir));
        foreach($lFiles as $sFile) {
            if (('.' != $sFile) && ('..' != $sFile)) {
                $sPath = realpath($sDir.'/'.$sFile);
                if (is_dir($sPath)) {
                    foreach($aPlugins as $oPlugin) {
                        if ($oPlugin->checkDirectories()) {
                            if ($oPlugin->check($sPath, null)) break;
                        }
                    }
                    scan($sPath, $aPlugins);
                }
                else {
                    $sContent = null;
                    foreach($aPlugins as $oPlugin) {
                        if ($oPlugin->filter($sPath)) {
                            if ($oPlugin->needFileContent() && !$sContent) $sContent = file_get_contents($sPath);
                            if ($oPlugin->check($sPath, $sContent)) break;
                        }
                    }
                }
            }
        }
    }
}

/**
 * Dummy plugins loader
 */
function loadPlugins($sPlugins, $sKind) {
    $lOO = array();
    foreach(explode(',', $sPlugins) as $sPlugin) {
        $sPlugin = trim($sPlugin);
        if ($sPlugin) {
            $sClass = trim($sPlugin.$sKind);
            $lOO[$sClass] = new $sClass();
        }
    }
    return $lOO;
}
function autoloadPlugins($sClass) {
    $sPath = dirname(__FILE__).'/plugins/check/'.$sClass.'.class.php';
    if (file_exists($sPath) && is_readable($sPath)) {
        include_once($sPath);
    }
    else {
        $sPath = dirname(__FILE__).'/plugins/report/'.$sClass.'.class.php';
        if (file_exists($sPath) && is_readable($sPath)) include_once($sPath);
    }
}

/**
 * Trace Malicious stop delay / status
 */
function _stop() {
    _log(sprintf('Malicious stop after %2.4fs. Completed status is %s', (_now() - MCS_START), (MCS_STOP ? 'OK.' : 'KO!')));
}

/**
 * Current time in usec
 *
 * @return float Current time in usec
 * @see    http://fr2.php.net/manual/fr/function.microtime.php
 */
function _now() {
    list($usec, $sec) = explode(' ', microtime());
    return ((float)$usec + (float)$sec);
}

/**
 * Log message to file
 *
 * @param string $sMsg  Message to log
 * @param string $sName Log name (.log will be appended)
 */
function _log($sMsg = '', $sName = 'malicious') {
    static $fd = null, $inc = 0;

    $sName      = (trim($sName) ? $sName : md5(date('Ymd')));
    $sPath      = MCS_LOGS.'/'.$sName.'.log';
    $fd[$sPath] = (isset($fd[$sPath]) ? $fd[$sPath] : fopen($sPath, 'a'));

    if ($fd[$sPath]) fwrite($fd[$sPath], sprintf("%04d|%s|%s\n", $inc++, date('d/m/y|H:i:s'), ($sMsg ? $sMsg : '!!!')));
}
function bytes($sSize) {
    switch (substr($sSize, -1)) {
        case 'M': case 'm': return (int)$sSize * 1048576;
        case 'K': case 'k': return (int)$sSize * 1024;
        case 'G': case 'g': return (int)$sSize * 1073741824;
        default: return $sSize;
    }
}
/**
 * Malicious "Check plugin" model
 */
class maliciousCheck {
    public $iCount = 0;         // Number of files checked
    public $lFiles = array();   // List of selected files

    function __construct() {
        //echo 'Load : '.get_class($this)."\n";
    }
    function check($sPath, $sContent = null) {
        $this->iCount++;
        return false;
    }
    function filter($sPath) {
        return true;
    }
    function warn() {
        return true;
    }
    function needFileContent() {
        return false;
    }
    function checkDirectories() {
        return false;
    }
    protected function extension($sPath) {
        return strtolower(pathinfo($sPath, PATHINFO_EXTENSION));
    }
    function __destruct() {
        //echo 'Unload : '.get_class($this)."\n";
    }
}

/**
 * Malicious "Check plugin" model
 */
class maliciousReport {
    function __construct() {
        //echo 'Load : '.get_class($this)."\n";
    }
    function report($lChecks) {
    }
    function __destruct() {
        //echo 'Unload : '.get_class($this)."\n";
    }
}
