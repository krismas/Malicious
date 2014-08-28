<?php
/**
 * Log check results to file
 *
 * @copyright Ackwa.fr - 2014
 */
class logReport extends maliciousReport {
    function report($lChecks) {
        foreach($lChecks as $oO) {
            _log(sprintf("%-60s [%-12s] : %4d / %4d", $oO->description(), str_replace('Check', '', get_class($oO)), count($oO->lFiles), $oO->iCount));
            if (count($oO->lFiles) && $oO->warn()) _log(print_r($oO->lFiles, true));
        }
    }
}