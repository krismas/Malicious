<?php
/**
 * Log check results to file
 */
class logReport extends maliciousReport {
    function report($lChecks) {
        foreach($lChecks as $oO) {
            _log("%-20s : %4d / %4d\n", get_class($oO), count($oO->lFiles), $oO->iCount);
            if (count($oO->lFiles) && $oO->warm()) _log(print_r($oO->lFiles, true));
        }
    }
}