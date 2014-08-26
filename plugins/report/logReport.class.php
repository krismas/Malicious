<?php
/**
 * Log check results to file
 *
 * @copyright Ackwa.fr - 2014
 */
class logReport extends maliciousReport {
    function report($lChecks) {
        foreach($lChecks as $oO) {
            _log(sprintf("%-20s : %4d / %4d", get_class($oO), count($oO->lFiles), $oO->iCount));
            if (count($oO->lFiles) && $oO->warm()) _log(print_r($oO->lFiles, true));
        }
    }
}