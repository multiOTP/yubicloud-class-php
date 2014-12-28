<?php
/**
 * @file  yubicloud.class.php
 * @brief Yubicloud LGPLv3 PHP class
 *
 * @mainpage
 *
 * Yubicloud PHP class - an all-in-one class to check YubiKeys using YubiCloud.
 * Validation Protocol Version 2.0 is implemented.
 * (https://code.google.com/p/yubikey-val-server-php/wiki/ValidationProtocolV20)
 *
 * No external file is needed (no PEAR, no PECL).
 *
 * The Yubicloud PHP class is a subset of the multiOTP open source project.
 *   (http://www.multiOTP.net/)
 *
 * PHP 5.3.0 or higher is supported.
 *
 * @author    Andre Liechti, SysCo systemes de communication sa, <info@multiotp.net>
 * @version   4.3.1.3
 * @date      2014-12-26
 * @since     2014-11-04
 * @copyright (c) 2014 SysCo systemes de communication sa
 * @copyright GNU Lesser General Public License
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
 *     $result = $yubicloud->CheckOnYubiCloud($otp_to_check);
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
 * @version   4.3.1.3
 * @date      2014-12-26
 * @since     2014-11-04
 */
{
    // How to get a Yubico API Key: https://upgrade.yubico.com/getapikey/
    var $_yubicloud_client_id       = 1;                   // YubiCloud default API client ID
    var $_yubicloud_secret_key      = '';                  // YubiCloud default API secret Key

    var $_yubicloud_timeout          = 10;                 // YubiCloud timeout in seconds
    var $_yubicloud_last_response    = array();            // YubiCloud last response array
    var $_yubicloud_last_result      = '';                 // YubiCloud last result (text)
    var $_yubicloud_max_time_window  = 600;                // YubiCloud maximum time window in seconds
	var $_yubico_modhex_chars        = "cbdefghijklnrtuv"; // ModHex values (instead of 0,1,2,3,4,5,6,7,8,9,0,a,b,c,d,e,f)

    
    function Yubicloud($yubicloud_client_id = 1, $yubicloud_secret_key = '')
    {
        if (1 < intval($yubicloud_client_id))
        {
            $this->_yubicloud_client_id = $yubicloud_client_id;
        }
        if (28 == strlen($yubicloud_secret_key))
        {
            $this->_yubicloud_secret_key = $yubicloud_secret_key;
        }
    }


    function SetYubicloudMaxTimeWindow($max_time)
    {
        if (intval($max_time) >= 1)
        {
            $this->yubicloud_max_time_window = intval($max_time);
        }
    }


    function CalculateHashHmac($algo, $data, $key, $raw_output = false)
    {
        if (function_exists('hash_hmac'))
        {
            return hash_hmac($algo, $data, $key, $raw_output);
        }
        else
        {
            /***********************************************************************
             * Simulate the function hash_hmac if it is not available
             *   (this function is natively available only for PHP >= 5.1.2)
             *
             * Source: http://www.php.net/manual/fr/function.hash-hmac.php#93440
             *
             * @author "KC Cloyd"
             ***********************************************************************/
            $algo = strtolower($algo);
            $pack = 'H'.strlen($algo('test'));
            $size = 64;
            $opad = str_repeat(chr(0x5C), $size);
            $ipad = str_repeat(chr(0x36), $size);

            if (strlen($key) > $size)
            {
                $key = str_pad(pack($pack, $algo($key)), $size, chr(0x00));
            }
            else
            {
                $key = str_pad($key, $size, chr(0x00));
            }

            for ($i = 0; $i < strlen($key) - 1; $i++)
            {
                $opad[$i] = $opad[$i] ^ $key[$i];
                $ipad[$i] = $ipad[$i] ^ $key[$i];
            }

            $output = $algo($opad.pack($pack, $algo($ipad.$data)));

            return ($raw_output) ? pack($pack, $output) : $output;
        }
    }


    function IsModHex($modhex)
    {
        $result = FALSE;
        if (0 == (strlen($modhex) % 2))
        {
            $result = TRUE;
            for ($loop = 0; $loop < strlen($modhex); $loop++)
            {
                if (FALSE === strpos($this->_yubico_modhex_chars, strtolower($modhex[$loop])))
                {
                    $result = FALSE;
                    break;
                }
            }
        }
		return $result;		
    }


    function GetYubiCloudLastResponse()
    {
        return $this->_yubicloud_last_response;
    }


    function GetYubiCloudLastResult()
    {
        return $this->_yubicloud_last_result;
    }


    function CheckOnYubiCloud($otp_to_check)
    /*
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
        $this->_yubicloud_last_response = array();
        $this->_yubicloud_last_result = 'NOT_ENOUGH_ANSWERS';
        $try_next_server = TRUE;
        $yubiotp = trim($otp_to_check);
        if ((44 == strlen($yubiotp)) && ($this->IsModHex($yubiotp)))
        {
            $yubicloud_servers = array('api.yubico.com/wsapi/2.0/verify',
                                       'api2.yubico.com/wsapi/2.0/verify',
                                       'api3.yubico.com/wsapi/2.0/verify',
                                       'api4.yubico.com/wsapi/2.0/verify',
                                       'api5.yubico.com/wsapi/2.0/verify');

            $yubicloud_parameters = array('id'        => $this->_yubicloud_client_id,
                                          'otp'       => $yubiotp,
                                          'timestamp' => 1,
                                          'nonce'     => md5(uniqid(rand())),
                                       /* 'sl'        => '', */ /* precentage of syncing not well documented */
                                          'timeout'   => $this->_yubicloud_timeout
                                         );

            // Parameters must be in the right order in order to calculate the hash
            ksort($yubicloud_parameters);

            $url_parameters = '';
            
            foreach($yubicloud_parameters as $key=>$value)
            {
                $url_parameters .= "&".$key."=".$value;
            }

            $url_parameters = substr($url_parameters, 1);
            
            if (28 == strlen($this->_yubicloud_secret_key))
            {
                $yubicloud_hash = urlencode(base64_encode($this->CalculateHashHmac('sha1',
                                                                                   $url_parameters,
                                                                                   base64_decode($this->_yubicloud_secret_key),
                                                                                   TRUE
                                                                                  )));
                $url_parameters.= '&h='.$yubicloud_hash;
            }
            
            foreach($yubicloud_servers as $one_yubicloud_server)
            {
                $yubicloud_answer = '';
                $yubicloud_url = $one_yubicloud_server.'?'.$url_parameters;
            
                $protocol = ''; // Default is http
                $port = 80;
                $pos = strpos($yubicloud_url, '://');
                if (FALSE !== $pos)
                {
                    switch (strtolower(substr($yubicloud_url,0,$pos)))
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
                    $yubicloud_url = substr($yubicloud_url,$pos+3);
                }

                $pos = strpos($yubicloud_url, '/');
                if (FALSE === $pos)
                {
                    $host = $yubicloud_url;
                    $url = '/';
                }
                else
                {
                    $host = substr($yubicloud_url,0,$pos);
                    $url = substr($yubicloud_url,$pos); // And not +1 as we want the / at the beginning
                }
                
                $pos = strpos($host, ':');
                if (FALSE !== $pos)
                {
                    $port = substr($host,$pos+1);
                    $host = substr($host,0,$pos);
                }
                
                $errno = 0;
                $errdesc = 0;
                $fp = @fsockopen($protocol.$host, $port, $errno, $errdesc, $this->_yubicloud_timeout);
                if (FALSE !== $fp)
                {
                    $info['timed_out'] = FALSE;
                    fputs($fp, "GET ".$url." HTTP/1.0\r\n");
                    fputs($fp, "Content-Type: application/x-www-form-urlencoded\r\n");
                    fputs($fp, "User-Agent: multiOTP\r\n");
                    fputs($fp, "Host: ".$host."\r\n");
                    fputs($fp, "\r\n");

                    stream_set_blocking($fp, TRUE);
                    stream_set_timeout($fp, $this->_yubicloud_timeout);
                    $info = stream_get_meta_data($fp); 
            
                    $reply = '';
                    $last_length = 0;
                    while ((!feof($fp)) && ((!$info['timed_out']) || ($last_length != strlen($reply))))
                    {
                        $last_length = strlen($reply);
                        $reply.= fgets($fp, 1024);
                        $info = stream_get_meta_data($fp);
                        @ob_flush(); // Avoid notice if any (if the buffer is empty and therefore cannot be flushed)
                        flush(); 
                    }
                    fclose($fp);

                    if (!($info['timed_out']))
                    {
                        $pos = strpos(strtolower($reply), "\r\n\r\n");
                        $header = substr($reply, 0, $pos);
                        $yubicloud_response = substr($reply, $pos + 4);
                        
                        $yubicloud_response_array = explode("\r\n", trim($yubicloud_response));
                        
                        $response = array();

                        $response['now_utc'] = date ("U");

                        foreach($yubicloud_response_array as $one_yubicloud_response)
                        {
                            /* '=' is also used in Base64, so we only explode the two first parts */
                            list($key,$value) = explode('=', $one_yubicloud_response, 2);
                            $response[$key] = $value;
                        }
                                            
                        $yubicloud_response_parameters = array('otp',
                                                               'nonce',
                                                               't',
                                                               'status',
                                                               'timestamp',
                                                               'sessioncounter',
                                                               'sessionuse',
                                                               'sl'
                                                              );

                        // Parameters must be in the right order in order to calculate the hash
                        sort($yubicloud_response_parameters);
                        
                        if (isset($response['t']))
                        {
                            $response['t_utc'] = date_format(date_create(substr($response['t'], 0, -4)), "U");
                        }

                        $parameters_for_hash = '';
                        foreach ($yubicloud_response_parameters as $one_parameter)
                        {
                            if (array_key_exists($one_parameter, $response))
                            {
                                if ('' != $parameters_for_hash)
                                {
                                    $parameters_for_hash.= '&';
                                }
                                $parameters_for_hash.= $one_parameter.'='.$response[$one_parameter];
                            }
                        }

                        $this->_yubicloud_last_response = $response;

                        $check_response_hash = "NO-VALID-SECRET-KEY";
                        if (28 == strlen($this->_yubicloud_secret_key))
                        {
                            $check_response_hash = base64_encode($this->CalculateHashHmac('sha1',
                                                                                          $parameters_for_hash,
                                                                                          base64_decode($this->_yubicloud_secret_key),
                                                                                          TRUE
                                                                                         ));
                        }
                        if (($check_response_hash != $response['h']) && ("NO-VALID-SECRET-KEY" != $check_response_hash))
                        {
                            $this->_yubicloud_last_result = 'BAD_SIGNATURE';
                            $try_next_server = TRUE;
                        }
                        elseif (isset($response['nonce']) && ($yubicloud_parameters['nonce'] != $response['nonce']))
                        {
                            $this->_yubicloud_last_result = 'BAD_NONCE';
                            $try_next_server = TRUE;
                        }
                        elseif (isset($response['otp']) && ($yubiotp != $response['otp']))
                        {
                            $this->_yubicloud_last_result = 'OTP_IS_DIFFERENT';
                            $try_next_server = TRUE;
                        }
                        elseif ((($response['t_utc'] - $this->_yubicloud_max_time_window) > $response['now_utc']) ||
                                (($response['t_utc'] + $this->_yubicloud_max_time_window) < $response['now_utc'])
                               )
                        {
                            $this->_yubicloud_last_result = 'OUT_OF_TIME_WINDOW';
                            $try_next_server = TRUE;
                        }
                        else
                        {
                            $this->_yubicloud_last_result = $response['status'];

                            switch ($this->_yubicloud_last_result)
                            {
                                case 'OK':
                                case 'BAD_OTP':
                                case 'MISSING_PARAMETER':
                                case 'NO_SUCH_CLIENT':
                                case 'REPLAYED_OTP':
                                case 'REPLAYED_REQUEST':
                                    $try_next_server = FALSE;
                                    break;
                                case 'BACKEND_ERROR':
                                case 'BAD_SIGNATURE':
                                case 'NOT_ENOUGH_ANSWERS':
                                case 'OPERATION_NOT_ALLOWED':
                                default:
                                    $try_next_server = TRUE;
                            }
                        }
                        if (!$try_next_server)
                        {
                            break;
                        }
                    }
                    else
                    {
                        $this->_yubicloud_last_result = 'SERVER_TIMEOUT';
                    }
                }
                else
                {
                    $this->_yubicloud_last_result = 'CONNECTION_ERROR';
                }
            }
        }
        else
        {
            $this->_yubicloud_last_result = 'BAD_OTP';
        }
        return $this->_yubicloud_last_result;
    }
}
?>