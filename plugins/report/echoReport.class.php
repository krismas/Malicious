<?php
/**
 * Echo check results to screen
 *
 * @copyright Ackwa.fr - 2014
 */
class echoReport extends maliciousReport {
    function report($lChecks) {
        if (isset($_SERVER['REMOTE_ADDR'])) echo '<pre>';
        foreach($lChecks as $oO) {
            printf("%-60s [%-12s] : %4d / %4d\n", $oO->description(), str_replace('Check', '', get_class($oO)), count($oO->lFiles), $oO->iCount);
            if (count($oO->lFiles) && $oO->warn()) print_r($oO->lFiles);
        }
        if (isset($_SERVER['REMOTE_ADDR'])) echo '</pre>';
    }
}