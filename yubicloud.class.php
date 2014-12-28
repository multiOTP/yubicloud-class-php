<?php
/**
 * @file  yubicloud.class.php
 * @brief Yubicloud LGPLv3 PHP class, verify YubiKey OTPs against YubiCloud
 *
 * @mainpage
 *
 * Yubicloud PHP class - an all-in-one class to check YubiKeys using YubiCloud.
 * Validation Protocol Version 2.0 is implemented.
 * (https://code.google.com/p/yubikey-val-server-php/wiki/ValidationProtocolV20)
 *
 * No external file is needed (no PEAR, no PECL, no cURL).
 *
 * The Yubicloud PHP class is a subset of the multiOTP open source project.
 *   (http://www.multiOTP.net/)
 *
 * PHP 5.3.0 or higher is supported.
 *
 * @author    Andre Liechti, SysCo systemes de communication sa, <info@multiotp.net>
 * @version   4.3.2.0
 * @date      2014-12-29
 * @since     2014-11-04
 * @copyright (c) 2014 SysCo systemes de communication sa
 * @license   GNU Lesser General Public License
 * @link      http://www.multiotp.net/
 *
 *//*
 *
 * LICENCE
 *
 *   Copyright (c) 2014 SysCo systemes de communication sa
 *   SysCo (tm) is a trademark of SysCo systemes de communication sa
 *   (http://www.sysco.ch/)
 *   All rights reserved.
 * 
 *   Yubicloud PHP class is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public License as
 *   published by the Free Software Foundation, either version 3 of the License,
 *   or (at your option) any later version.
 * 
 *   Yubicloud PHP class is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU Lesser General Public License for more details.
 * 
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with Yubicloud PHP class.
 *   If not, see <http://www.gnu.org/licenses/>.
 *
 *
 * Usage
 *
 *   You need a free Yubico API key. You can ask for your own key here:
 *     https://upgrade.yubico.com/getapikey/
 *
 *   <?php
 *     require_once('yubicloud.class.php');
 *     $yubicloud = new Yubicloud("my_client_id", "my_secret_key");
 *     $result = $yubicloud->checkOnYubiCloud($otp_to_check);
 *   ?>
 *
 *   Possible returned value is one of the following:
 *                      OK  The OTP is valid.
 *                 BAD_OTP  The OTP is invalid format.
 *            REPLAYED_OTP  The OTP has already been seen by the service.
 *           BAD_SIGNATURE  The HMAC signature verification failed.
 *       MISSING_PARAMETER  The request lacks a parameter.
 *          NO_SUCH_CLIENT  The request id does not exist.
 *   OPERATION_NOT_ALLOWED  The request id is not allowed to verify OTPs.
 *           BACKEND_ERROR  Unexpected error in Yubico servers. Please contact them if you see this error.
 *      NOT_ENOUGH_ANSWERS  Server could not get requested number of syncs during before timeout.
 *        REPLAYED_REQUEST  Server has seen the OTP/Nonce combination before.
 *               BAD_NONCE  Answer Nonce is different from the request Nonce.
 *        CONNECTION_ERROR  Impossible to make a connection with the YubiCloud servers.
 *        OTP_IS_DIFFERENT  Answer OTP is different from request OTP.
 *      OUT_OF_TIME_WINDOW  Timestamp difference with the Yubico servers is bigger than yubicloud_max_time_window.
 *          SERVER_TIMEOUT  Timeout while waiting an answer from the server.
 *
 *   Check yubicloud.demo.php for a full implementation example.
 *
 *
 * Change Log
 *
 *   2014-12-29 4.3.2.0 SysCo/al Concurrent multiple requests (still without cURL)
 *                               Some modifications for future PSR compliance (http://www.php-fig.org/)
 *   2014-12-26 4.3.1.3 SysCo/al Better hash_hmac integration
 *   2014-12-22 4.3.1.2 SysCo/al Additional check
 *   2014-11-04 4.3.0.0 SysCo/al Initial release, version number is synchronized with the multiOTP project
 *********************************************************************/


class Yubicloud
/**
 * @class     Yubicloud
 * @brief     Class definition for Yubicloud handling.
 *
 * @author    Andre Liechti, SysCo systemes de communication sa, <info@multiotp.net>
 * @version   4.3.2.0
 * @date      2014-12-29
 * @since     2014-11-04
 */
{
    var $_yubicloud_client_id      = 1;     // YubiCloud default API client ID
    var $_yubicloud_secret_key     = '';    // YubiCloud default API secret Key
    var $_yubicloud_https          = false; // By default, do not use https
    var $_yubicloud_urls           = array('api5.yubico.com/wsapi/2.0/verify',
                                           'api4.yubico.com/wsapi/2.0/verify',
                                           'api3.yubico.com/wsapi/2.0/verify',
                                           'api2.yubico.com/wsapi/2.0/verify',
                                           'api.yubico.com/wsapi/2.0/verify');

    var $_yubicloud_timeout         = 10;      // YubiCloud timeout in seconds
    var $_yubicloud_last_response   = array(); // YubiCloud last response array
    var $_yubicloud_last_result     = '';      // YubiCloud last result (text)
    var $_yubicloud_max_time_window = 600;     // YubiCloud maximum time window in seconds

	const YUBICO_MODHEX_CHARS = "cbdefghijklnrtuv"; // ModHex values (instead of 01234567890abcdef)


    function Yubicloud($yubicloud_client_id = 1, $yubicloud_secret_key = '', $yubicloud_https = false)
    /**
     * @brief   Class constructor.
     *
     * Sets up the object
     * @param string  $yubicloud_client_id   The client identity (optional, default 1)
     * @param string  $yubicloud_secret_key  The client MAC key (optional, default '')
     * @param boolean $yubicloud_https       Flag whether to use https (optional, default false)
     * @retval  void
     *
     * @author  Andre Liechti, SysCo systemes de communication sa, <info@multiotp.net>
     * @version 4.3.2.0
     * @date    2014-12-29
     * @since   2014-11-04
     */
    {
        if (0 < intval($yubicloud_client_id)) {
            $this->_yubicloud_client_id = $yubicloud_client_id;
        }
        if (28 == strlen($yubicloud_secret_key)) {
            $this->_yubicloud_secret_key = $yubicloud_secret_key;
        }
        $this->_yubicloud_https = (true === $yubicloud_https);
    }


    function setYubicloudMaxTimeWindow($max_time)
    /**
     * @brief   Set the timeout when talking to the YubiCloud servers
     *
     * @param   int $max_time  Maximum time to wait for an answer
     * @retval  void
     *
     * @author  Andre Liechti, SysCo systemes de communication sa, <info@multiotp.net>
     * @version 4.3.2.0
     * @date    2014-12-29
     * @since   2014-11-04
     */
    {
        if (intval($max_time) >= 1) {
            $this->_yubicloud_max_time_window = intval($max_time);
        }
    }


    function calculateHashHmac($algo, $data, $key, $raw_output = false)
    /**
     * @brief   Simulate the function hash_hmac if it is not available
     *
     * (the hash_hmac function is natively available only for PHP >= 5.1.2)
     *
     * @param   string  $algo        Name of selected hashing algorithm (sha1, md5, etc.)
     * @param   string  $data        Message to be hashed
     * @param   string  $key         Shared secret key used for generating the HMAC
     * @param   boolean $raw_output  When set to TRUE, outputs raw binary data
     * @retval  string               Calculated message digest as lowercase hexits
     *
     * Source: http://www.php.net/manual/fr/function.hash-hmac.php#93440
     *
     * @author "KC Cloyd"
     */
    {
        if (function_exists('hash_hmac')) {
            return hash_hmac($algo, $data, $key, $raw_output);
        } else {
            $algo = strtolower($algo);
            $pack = 'H'.strlen($algo('test'));
            $size = 64;
            $opad = str_repeat(chr(0x5C), $size);
            $ipad = str_repeat(chr(0x36), $size);

            if (strlen($key) > $size) {
                $key = str_pad(pack($pack, $algo($key)), $size, chr(0x00));
            } else {
                $key = str_pad($key, $size, chr(0x00));
            }

            for ($i = 0; $i < strlen($key) - 1; $i++) {
                $opad[$i] = $opad[$i] ^ $key[$i];
                $ipad[$i] = $ipad[$i] ^ $key[$i];
            }

            $output = $algo($opad.pack($pack, $algo($ipad.$data)));

            return ($raw_output) ? pack($pack, $output) : $output;
        }
    }


    function isModHex($modhex)
    /**
     * @brief   Check the string to know if it is a ModHex or not
     *
     * @param   string  $modhex  String to check
     * @retval  boolean          Return true if it is a ModHex string
     *
     * @author  Andre Liechti, SysCo systemes de communication sa, <info@multiotp.net>
     * @version 4.3.2.0
     * @date    2014-12-29
     * @since   2014-11-04
     */
    {
        $result = false;
        if (0 == (strlen($modhex) % 2)) {
            $result = true;
            for ($loop = 0; $loop < strlen($modhex); $loop++) {
                if (false === strpos(self::YUBICO_MODHEX_CHARS, strtolower($modhex[$loop]))) {
                    $result = false;
                    break;
                }
            }
        }
		return $result;		
    }


    function getYubiCloudLastResponse()
    /**
     * @brief   Return the last response from the server (as an array)
     *
     * @retval  array  Last repsonse from the server
     *
     * @author  Andre Liechti, SysCo systemes de communication sa, <info@multiotp.net>
     * @version 4.3.2.0
     * @date    2014-12-29
     * @since   2014-11-04
     */
    {
        return $this->_yubicloud_last_response;
    }


    function getYubiCloudLastResult()
    /**
     * @brief   Return the result of the last check
     *
     * @retval  string  Result of the last check
     *
     * @author  Andre Liechti, SysCo systemes de communication sa, <info@multiotp.net>
     * @version 4.3.2.0
     * @date    2014-12-29
     * @since   2014-11-04
     */
    {
        return $this->_yubicloud_last_result;
    }


    function checkOnYubiCloud($otp_to_check)
    /**
     * @brief   Check Yubico OTP against multiple URLs on the YubiCloud servers
     *
     * @param   string  $otp_to_check  Yubico OTP to check
     * @retval  string                 Result of the verification (see below)
     *
     * @author  Andre Liechti, SysCo systemes de communication sa, <info@multiotp.net>
     * @version 4.3.2.0
     * @date    2014-12-29
     * @since   2014-11-04
     *
     *
     * Validation Protocol Version 2.0 is implemented
     *   (https://code.google.com/p/yubikey-val-server-php/wiki/ValidationProtocolV20)
     *
     * Possible returned value is one of the following:
     *                    OK  The OTP is valid.
     *               BAD_OTP  The OTP is invalid format.
     *          REPLAYED_OTP  The OTP has already been seen by the service.
     *         BAD_SIGNATURE  The HMAC signature verification failed.
     *     MISSING_PARAMETER  The request lacks a parameter.
     *        NO_SUCH_CLIENT  The request id does not exist.
     * OPERATION_NOT_ALLOWED  The request id is not allowed to verify OTPs.
     *         BACKEND_ERROR  Unexpected error in Yubico servers. Please contact them if you see this error.
     *    NOT_ENOUGH_ANSWERS  Server could not get requested number of syncs during before timeout.
     *      REPLAYED_REQUEST  Server has seen the OTP/Nonce combination before.
     *             BAD_NONCE  Answer Nonce is different from the request Nonce.
     *      CONNECTION_ERROR  Impossible to make a connection with the YubiCloud servers.
     *      OTP_IS_DIFFERENT  Answer OTP is different from request OTP.
     *    OUT_OF_TIME_WINDOW  Timestamp difference with the Yubico servers is bigger than yubicloud_max_time_window.
     *        SERVER_TIMEOUT  Timeout while waiting an answer from the server.
     */
    {
        $servers_done    = 0;
        $replies         = array();
        $replayed        = false;
        $validated       = false;

        $this->_yubicloud_last_response = array();
        $this->_yubicloud_last_result   = 'CONNECTION_ERROR';

        $yubiotp = trim($otp_to_check);

        if ((44 == strlen($yubiotp)) && ($this->isModHex($yubiotp))) {
            $yubicloud_parameters = array('id'        => $this->_yubicloud_client_id,
                                          'otp'       => $yubiotp,
                                          'timestamp' => 1,
                                          'nonce'     => md5(uniqid(rand())),
                                       /* 'sl'        => '', */ /* percentage of syncing not well documented */
                                          'timeout'   => $this->_yubicloud_timeout
                                         );

            // Parameters must be in the right order in order to calculate the hash
            ksort($yubicloud_parameters);

            $url_parameters = '';
            
            foreach ($yubicloud_parameters as $key=>$value) {
                $url_parameters .= "&".$key."=".$value;
            }

            $url_parameters = substr($url_parameters, 1);
            
            if (28 == strlen($this->_yubicloud_secret_key)) {
                $yubicloud_hash = urlencode(base64_encode($this->calculateHashHmac('sha1',
                                                                                   $url_parameters,
                                                                                   base64_decode($this->_yubicloud_secret_key),
                                                                                   true
                                                                                  )));
                $url_parameters.= '&h='.$yubicloud_hash;
            }

            $server_index = 0;
            foreach ($this->_yubicloud_urls as $one_url) {
                $url = $one_url.'?'.$url_parameters;
                
                $protocol = ($this->_yubicloud_https?"ssl://":""); // Default is empty (http)
                $port = ($this->_yubicloud_https?443:80);
                $pos = strpos($url, '://');
                if (false !== $pos) {
                    switch (strtolower(substr($url,0,$pos)))
                    {
                        case 'https':
                        case 'ssl':
                            $protocol = 'ssl://';
                            $port = 443;
                            break;
                        case 'tls':
                            $protocol = 'tls://';
                            $port = 443;
                            break;
                    }
                    $url = substr($url,$pos+3);
                }

                $pos = strpos($url, '/');
                if (false === $pos) {
                    $host = $url;
                    $url = '/';
                } else {
                    $host = substr($url,0,$pos);
                    $url = substr($url,$pos); // And not +1 as we want the / at the beginning
                }
                
                $pos = strpos($host, ':');
                if (false !== $pos) {
                    $port = substr($host,$pos+1);
                    $host = substr($host,0,$pos);
                }
                
                $errno = 0;
                $errdesc = 0;

                $replies['server'][$server_index] = $protocol.$host;
                $replies['url'][$server_index] = $url;
                $replies['reply'][$server_index] = '';
                $replies['last_length'][$server_index] = 0;

                $fp = @fsockopen($protocol.$host, $port, $errno, $errdesc, $this->_yubicloud_timeout);

                if (false !== $fp) {
                    $replies['done'][$server_index] = false;
                    $replies['info'][$server_index]['timed_out'] = false;
                    fputs($fp, "GET ".$url." HTTP/1.0\r\n");
                    fputs($fp, "Content-Type: application/x-www-form-urlencoded\r\n");
                    fputs($fp, "User-Agent: multiOTP\r\n");
                    fputs($fp, "Host: ".$host."\r\n");
                    fputs($fp, "\r\n");

                    stream_set_blocking($fp, false);
                    stream_set_timeout($fp, $this->_yubicloud_timeout);
                    $replies['info'][$server_index] = stream_get_meta_data($fp); 
                } else {
                    $replies['done'][$server_index] = true;
                    $replies['result'][$server_index] = "CONNECTION_ERROR";
                    $servers_done++;
                }

                $replies['fp'][$server_index] = $fp;
                $server_index++;
            }
            
            $loop_on_servers = true;

            $start_epoch = time();
            while (($loop_on_servers) && ($servers_done < count($this->_yubicloud_urls))) {
                $read_array = null;
                foreach ($replies['fp'] as $key => $pointer) {
                    if ((!$replies['done'][$key]) && (is_resource($pointer))) {
                        $read_array[] = $pointer;
                    }
                }
                $write_array  = null;
                $except_array = null;
                if (false === ($num_changed_streams = stream_select(
                    $read_array,
                    $write_array,
                    $except_array,
                    0,
                    200000 // 0.2 second timeout to reduce CPU usage
                   ))) {
                    $loop_on_servers = false;
                } else {
                    foreach ($replies['fp'] as $key => $pointer) {
                        if (!$validated && !$replayed && (!$replies['done'][$key]) && (is_resource($pointer))) {
                            $replies['info'][$key] = stream_get_meta_data($pointer);
                            if ($replies['info'][$key]['timed_out']) {
                                $replies['done'][$key] = true;
                                $replies['result'][$key] = "SERVER_TIMEOUT";
                                $servers_done++;
                            }
                        }
                        if (!$validated && !$replayed && ($num_changed_streams > 0)) {
                            foreach ($read_array as $read_pointer) {
                                if ($pointer == $read_pointer) {
                                    if ((!$replies['done'][$key]) && (is_resource($pointer))) {
                                        $fp = $replies['fp'][$key];
                                        $replies['last_length'][$key] = strlen($replies['reply'][$key]);
                                        $replies['reply'][$key].= fgets($fp, 1024);
                                        $replies['info'][$key] = stream_get_meta_data($fp);
                                        if (feof($fp)) {
                                            $reply = $replies['reply'][$key];
                                            $pos = strpos(strtolower($reply), "\r\n\r\n");
                                            $header = substr($reply, 0, $pos);
                                            $body = substr($reply, $pos + 4);
                                            $reply_array = explode("\r\n", trim($body));
                                            
                                            $response = array();
                                            $response['now_utc'] = date ("U");

                                            foreach ($reply_array as $one_response) {
                                                /* '=' is also used in Base64, so we only explode the two first parts */
                                                list($key,$value) = explode('=', $one_response, 2);
                                                $response[$key] = $value;
                                            }
                                                                
                                            $response_parameters = array('otp',
                                                                         'nonce',
                                                                         't',
                                                                         'status',
                                                                         'timestamp',
                                                                         'sessioncounter',
                                                                         'sessionuse',
                                                                         'sl'
                                                                        );

                                            // Parameters must be in the right order in order to calculate the hash
                                            sort($response_parameters);
                                            
                                            if (isset($response['t'])) {
                                                $response['t_utc'] = date_format(date_create(substr($response['t'], 0, -4)), "U");
                                            }

                                            $parameters_for_hash = '';
                                            foreach ($response_parameters as $one_parameter) {
                                                if (array_key_exists($one_parameter, $response)) {
                                                    if ('' != $parameters_for_hash) {
                                                        $parameters_for_hash.= '&';
                                                    }
                                                    $parameters_for_hash.= $one_parameter.'='.$response[$one_parameter];
                                                }
                                            }

                                            $this->_yubicloud_last_response = $response;

                                            $check_response_hash = "NO-VALID-SECRET-KEY";
                                            if (28 == strlen($this->_yubicloud_secret_key)) {
                                                $check_response_hash = base64_encode($this->calculateHashHmac('sha1',
                                                                                                              $parameters_for_hash,
                                                                                                              base64_decode($this->_yubicloud_secret_key),
                                                                                                              true
                                                                                                             ));
                                            }
                                            if (($check_response_hash != $response['h']) && ("NO-VALID-SECRET-KEY" != $check_response_hash)) {
                                                $this->_yubicloud_last_result = 'BAD_SIGNATURE';
                                            } elseif (isset($response['nonce']) && ($yubicloud_parameters['nonce'] != $response['nonce'])) {
                                                $this->_yubicloud_last_result = 'BAD_NONCE';
                                            } elseif (isset($response['otp']) && ($yubiotp != $response['otp'])) {
                                                $this->_yubicloud_last_result = 'OTP_IS_DIFFERENT';
                                            } elseif ((($response['t_utc'] - $this->_yubicloud_max_time_window) > $response['now_utc']) ||
                                                    (($response['t_utc'] + $this->_yubicloud_max_time_window) < $response['now_utc'])
                                                   ) {
                                                $this->_yubicloud_last_result = 'OUT_OF_TIME_WINDOW';
                                            } else {
                                                $this->_yubicloud_last_result = $response['status'];

                                                switch ($response['status'])
                                                {
                                                    case 'OK':
                                                        $validated = true;
                                                        break;
                                                    case 'REPLAYED_OTP':
                                                        $replayed = true;
                                                        break;
                                                }
                                            }
                                                                            
                                            $replies['done'][$key] = true;
                                            $replies['result'][$key] = $response['status'];
                                            $servers_done++;
                                            fclose($fp);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                if (
                    $validated ||
                    $replayed ||
                    ($start_epoch + $this->_yubicloud_max_time_window < time())
                   ) {
                    $loop_on_servers = false;
                }
            }
        } else {
            $this->_yubicloud_last_result = 'BAD_OTP';
        }
        
        return $this->_yubicloud_last_result;
    }
}
