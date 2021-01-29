<?php
/**
 * HF API Class
 * Easily connect to and use HF API v2
 *
 * by Xerotic
 */
class HF_API
{
    private $client_id;
    private $secret_key;
    private $access_token;
    private $uid;
    private $errors = [];
    private $state;
    private $authorize_url = "https://hackforums.net/api/v2/authorize";
    private $read_url = "https://hackforums.net/api/v2/read";
    private $write_url = "https://hackforums.net/api/v2/write";

    /**
     * HF API constructor. Initializes the HF API class.
     * @constructor method
     */
    public function __construct()
    {
        $this->changeState();
    }
    
    /**
     * Sets your application's Client ID.
     *
     * @param string $client_id
     * Your application's Client ID. You can find it at https://hackforums.net/usercp.php?action=apideveloper
     */
    public function setClientID($client_id)
    {
        $this->client_id = $client_id;
    }

    /**
     * Sets your application's Secret Key.
     *
     * @param string $secret_key
     * Your application's Secret Key. You can find it at https://hackforums.net/usercp.php?action=apideveloper
     */
    public function setSecretKey($secret_key)
    {
        $this->secret_key = $secret_key;
    }

    /**
     * Gets the Access Token for the authorized member.
     *
     * @return mixed Returns the Access Token <b>STRING</b>. If it was not set yet, the return value is <b>NULL</b>.
     */
    public function getAccessToken()
    {
        return $this->access_token;
    }
    
    /**
     * Sets the Access Token for the authorized member.
     *
     * @param string $access_token
     * The Access Token of the authorized member.
     */
    public function setAccessToken($access_token)
    {
        $this->access_token = preg_replace("/[^A-Za-z0-9]/", "", $access_token);
    }
    
    /**
     * Checks if the Access Token is set.
     * @return bool
     */
    private function checkAccessToken()
    {
        if (is_null($this->access_token)) {
            $this->setError('ACCESS_TOKEN_NOT_SET');
            return false;
        }

        return true;
    }

    /**
     * Gets the authorized member's HF UID.
     *
     * @return mixed Returns the Access Token <b>STRING</b>. If it was not set yet, the return value is <b>NULL</b>.
     */
    public function getUID()
    {
        return $this->uid;
    }
    
    /**
     * Sets the error array.
     *
     * @param string $error
     */
    private function setError($error)
    {
        $this->errors[] = $error;
    }
    
    /**
     * Returns an array of errors.
     *
     * @return array
     */
    public function getErrors()
    {
        return $this->errors;
    }
    
    /**
     * Changes the state.
     *
     * @return false|string
     */
    private function changeState()
    {
        $this->state = substr(str_shuffle(MD5(microtime())), 0, 12);

        return $this->state;
    }
    
    /**
     * Sets the state.
     *
     * @param string $state
     */
    public function setState($state)
    {
        $this->state = preg_replace("/[^A-Za-z0-9]/", "", $state);
    }
    
    /**
     * Gets the state.
     *
     * @return string Returns the state <b>STRING</b>.
     */
    public function getState()
    {
        return $this->state;
    }

    /**
     * cURL request wrapper.
     *
     * @param $url
     * @param $post_fields
     * @param array $http_headers
     * @return bool|string
     */
    private function sendCurl($url, $post_fields, $http_headers = [])
    {
        $ch = curl_init();

        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $post_fields);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 0);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');

        if (!empty($http_headers)) {
            curl_setopt($ch, CURLOPT_HTTPHEADER, $http_headers);
        }

        $response = curl_exec($ch);

        curl_close($ch);

        return $response;
    }

    /**
     * Starts the authentication process.
     *
     * @return bool Redirects the user to the authentication panel on HF. If the Client ID wasn't set, it will return <b>FALSE</b>.
     */
    public function startAuth()
    {
        if (is_null($this->client_id)) {
            $this->setError('CLIENT_ID_NOT_SET');
            return false;
        }

        header("Location: {$this->authorize_url}?response_type=code&client_id={$this->client_id}&state={$this->state}");
        exit;
    }
    
    /**
     * Finishes the authentication procedure.
     *
     * @param string $state
     * The state of the authentication. (optional)
     * @return bool
     * If everything went good it returns <b>TRUE</b>, otherwise returns <b>FALSE</b>.
     */
    public function finishAuth($state = "")
    {
        $state = preg_replace("/[^A-Za-z0-9]/", "", $state);

        $input = array_change_key_case($_GET, CASE_LOWER);

        $code = preg_replace("/[^A-Za-z0-9]/", "", $input['code']);

        if (!empty($state) && trim($input['state']) != trim($state)) {
            $this->setError('INVALID_STATE');
            return false;
        }

        if (empty($code)) {
            $this->setError('INVALID_CODE');
            return false;
        }

        if (is_null($this->client_id)) {
            $this->setError('CLIENT_ID_NOT_SET');
            return false;
        }

        if (is_null($this->secret_key)) {
            $this->setError('SECRET_KEY_NOT_SET');
            return false;
        }

        $response = $this->sendCurl($this->authorize_url, [
            'grant_type' => "authorization_code",
            'client_id' => $this->client_id,
            'client_secret' => $this->secret_key,
            'code' => $code
        ]);

        if (empty($response)) {
            $this->setError('BAD_RESPONSE_FROM_HF_OR_CURL_ERROR');
            return false;
        }

        try {
            $response = json_decode($response, true);
        } catch (Exception $e) {
            $this->setError('BAD_RESPONSE_FROM_HF');
            return false;
        }

        if (array_key_exists("success", $response) && $response['success'] == false) {
            if (array_key_exists("message", $response)) {
                $this->setError($response['message']);
            } else {
                $this->setError('BAD_RESPONSE_FROM_HF');
            }
            return false;
        }

        if (!array_key_exists("access_token", $response)) {
            $this->setError('BAD_RESPONSE_FROM_HF');
            return false;
        }

        $this->access_token = $response['access_token'];
        $this->uid = $response['uid'];

        return true;
    }
    
    /**
     * Reads from HF API.
     *
     * @param array $asks
     * The array of data you want to read.
     * @return bool|array If everything went good it returns the response <b>ARRAY</b>, otherwise returns <b>FALSE</b>.
     */
    public function read($asks)
    {
        if (!$this->checkAccessToken()) {
            return false;
        }

        if (empty($asks)) {
            $this->setError('NO_DATA_REQUESTED');
            return false;
        }

        $response = $this->sendCurl($this->read_url, [
            'asks' => json_encode($asks)
        ], ["Authorization: Bearer {$this->access_token}"]);

        if (empty($response)) {
            $this->setError('BAD_RESPONSE_FROM_HF_OR_CURL_ERROR');
            return false;
        }

        try {
            $response = json_decode($response, true);
        } catch (Exception $e) {
            $this->setError('BAD_RESPONSE_FROM_HF');
            return false;
        }

        if (array_key_exists("success", $response) && $response['success'] == false) {
            if (array_key_exists("message", $response)) {
                $this->setError($response['message']);
            } else {
                $this->setError('BAD_RESPONSE_FROM_HF');
            }
            return false;
        }

        return $response;
    }

    /**
     * Writes to HF API.
     *
     * @param array $asks
     * The array of data you want to write.
     * @return bool|array If everything went good it returns the response <b>ARRAY</b>, otherwise returns <b>FALSE</b>.
     */
    public function write($asks)
    {
        if (!$this->checkAccessToken()) {
            return false;
        }

        if (empty($asks)) {
            $this->setError('NO_DATA_REQUESTED');
            return false;
        }

        $response = $this->sendCurl($this->write_url, [
            'asks' => json_encode($asks)
        ], ["Authorization: Bearer {$this->access_token}"]);

        if (empty($response)) {
            $this->setError('BAD_RESPONSE_FROM_HF_OR_CURL_ERROR');
            return false;
        }

        try {
            $response = json_decode($response, true);
        } catch (Exception $e) {
            $this->setError('BAD_RESPONSE_FROM_HF');
            return false;
        }

        if (!is_array($response)) {
            $response = [];
        }

        if (array_key_exists("success", $response) && $response['success'] == false) {
            if (array_key_exists("message", $response)) {
                $this->setError($response['message']);
            } else {
                $this->setError('BAD_RESPONSE_FROM_HF');
            }
            return false;
        }

        return $response;
    }

    /**
     * Makes a post.
     *
     * @param int|string $tid
     * Thread ID
     * @param string $message
     * Message
     * @return bool|array If everything went good it returns the response <b>ARRAY</b>, otherwise returns <b>FALSE</b>.
     */
    public function makePost($tid, $message)
    {
        if (!$this->checkAccessToken()) {
            return false;
        }

        $tid = (int)$tid;
        if ($tid <= 0) {
            $this->setError('NO_TID_SET');
            return false;
        }

        if (empty($message) || mb_strlen($message) < 3) {
            $this->setError('NO_MESSAGE_SET');
            return false;
        }

        return $this->write([
            "posts" => [
                "_tid" => $tid,
                "_message" => $message
            ]
        ]);
    }

    /**
     * Makes a thread.
     *
     * @param int|string $fid
     * Forum ID
     * @param string $subject
     * Subject
     * @param string $message
     * Message
     * @return bool|array If everything went good it returns the response <b>ARRAY</b>, otherwise returns <b>FALSE</b>.
     */
    public function makeThread($fid, $subject, $message)
    {
        if (!$this->checkAccessToken()) {
            return false;
        }

        $fid = (int)$fid;
        if ($fid <= 0) {
            $this->setError('NO_FID_SET');
            return false;
        }

        if (empty($subject) || mb_strlen($subject) < 3) {
            $this->setError('NO_SUBJECT_SET');
            return false;
        }

        if (empty($message) || mb_strlen($message) < 3) {
            $this->setError('NO_MESSAGE_SET');
            return false;
        }

        return $this->write([
            "threads" => [
                "_fid" => $fid,
                "_subject" => $subject,
                "_message" => $message
            ]
        ]);
    }

    /**
     * Sends bytes to a specified HF member.
     *
     * @param int|string $uid
     * UID of the beneficiary member
     * @param int|float|string $amount
     * Amount of bytes to be sent
     * @param string $reason
     * Reason (optional)
     * @param int|string $pid
     * Post ID (optional)
     * @return bool|array If everything went good it returns the response <b>ARRAY</b>, otherwise returns <b>FALSE</b>.
     */
    public function sendBytes($uid, $amount, $reason = "", $pid = 0)
    {
        if (!$this->checkAccessToken()) {
            return false;
        }

        $uid = (int)$uid;
        if ($uid <= 0) {
            $this->setError('NO_UID_SET');
            return false;
        }

        $amount = (int)$amount;
        if ($amount <= 0) {
            $this->setError('NO_AMOUNT_SET');
            return false;
        }

        if (!empty($reason) && mb_strlen($reason) > 192) {
            $this->setError('REASON_MAX_LENGTH_EXCEEDED_192');
            return false;
        }

        return $this->write([
            "bytes" => [
                "_uid" => $uid,
                "_amount" => $amount,
                "_reason" => $reason,
                "_pid" => $pid
            ]
        ]);
    }

    /**
     * Returns the Vault's balance.
     *
     * @return bool|int If everything went good it returns the Vault's balance <b>(int)</b>, otherwise returns <b>0</b>.
     */
    public function vaultBalance()
    {
        if (!$this->checkAccessToken()) {
            return false;
        }

        $read_vault = $this->read([
            "me" => [
                "vault" => true
            ]
        ]);

        if (!is_array($read_vault) || !array_key_exists('me', $read_vault) || !is_array($read_vault['me']) || !array_key_exists('vault', $read_vault['me'])) {
            return 0;
        }

        return (int)$read_vault['me']['vault'];
    }
    
    /**
     * Deposits to the Vault.
     *
     * @param int|float|string $amount
     * Amount to deposit
     * @return bool|array If everything went good it returns the response <b>ARRAY</b>, otherwise returns <b>FALSE</b>.
     */
    public function vaultDeposit($amount)
    {
        if (!$this->checkAccessToken()) {
            return false;
        }

        $amount = (int)$amount;
        if ($amount <= 0) {
            $this->setError('NO_AMOUNT_SET');
            return false;
        }

        return $this->write([
            "bytes" => [
                "_deposit" => $amount
            ]
        ]);
    }

    /**
     * Withdraws from the Vault.
     *
     * @param int|float|string $amount
     * Amount to withdraw
     * @return bool|array If everything went good it returns the response <b>ARRAY</b>, otherwise returns <b>FALSE</b>.
     */
    public function vaultWithdraw($amount)
    {
        if (!$this->checkAccessToken()) {
            return false;
        }

        $amount = (int)$amount;
        if ($amount <= 0) {
            $this->setError('NO_AMOUNT_SET');
            return false;
        }

        return $this->write([
            "bytes" => [
                "_withdraw" => $amount
            ]
        ]);
    }
    
    /**
     * Makes a new Contract.
     *
     * @param array $ask
     * The array of data you want to write.
     * @return bool|array If everything went good it returns the response <b>ARRAY</b>, otherwise returns <b>FALSE</b>.
     */
    public function newContract($ask)
    {
        if (!$this->checkAccessToken()) {
            return false;
        }

        $data = [
            '_uid' => array_key_exists('_uid', $ask) ? $ask['_uid'] : 0,
            '_theirproduct' => array_key_exists('_theirproduct', $ask) ? $ask['_theirproduct'] : "",
            '_theircurrency' => array_key_exists('_theircurrency', $ask) ? $ask['_theircurrency'] : "",
            '_theiramount' => array_key_exists('_theiramount', $ask) ? $ask['_theiramount'] : 0,
            '_yourproduct' => array_key_exists('_yourproduct', $ask) ? $ask['_yourproduct'] : "",
            '_yourcurrency' => array_key_exists('_yourcurrency', $ask) ? $ask['_yourcurrency'] : "",
            '_youramount' => array_key_exists('_youramount', $ask) ? $ask['_youramount'] : 0,
            '_tid' => array_key_exists('_tid', $ask) ? $ask['_tid'] : 0,
            '_muid' => array_key_exists('_muid', $ask) ? $ask['_muid'] : 0,
            '_timeout' => array_key_exists('_timeout', $ask) ? $ask['_timeout'] : 14,
            '_position' => array_key_exists('_position', $ask) ? $ask['_position'] : "",
            '_terms' => array_key_exists('_terms', $ask) ? $ask['_terms'] : "",
            '_public' => (array_key_exists('_public', $ask) && $ask['_public']) ? "yes" : "",
            '_address' => array_key_exists('_address', $ask) ? $ask['_address'] : ""
        ];

        if ($data['_uid'] <= 0) {
            $this->setError('NO_UID_SET_IN_DATA_ARRAY');
            return false;
        }

        if (empty($data['_position'])) {
            $this->setError('NO_POSITION_SET_IN_DATA_ARRAY');
            return false;
        }

        if (empty($data['_terms'])) {
            $this->setError('NO_TERMS_SET_IN_DATA_ARRAY');
            return false;
        }

        $write = [
            "contracts" => [
                "_action" => "new"
            ]
        ];

        foreach ($data as $key => $field) {
            $write['contracts'][$key] = $field;
        }

        return $this->write($write);
    }

    /**
     * Undo the Contract.
     *
     * @param int|string $cid
     * The Contract's ID
     * @return bool|array If everything went good it returns the response <b>ARRAY</b>, otherwise returns <b>FALSE</b>.
     */
    public function undoContract($cid)
    {
        if (!$this->checkAccessToken()) {
            return false;
        }

        $cid = (int)$cid;
        if ($cid <= 0) {
            $this->setError('NO_CID_SET');
            return false;
        }

        return $this->write([
            "contracts" => [
                "_cid" => $cid,
                "_action" => "undo"
            ]
        ]);
    }
    
    /**
     * Denies the Contract.
     *
     * @param int|string $cid
     * The Contract's ID
     * @return bool|array If everything went good it returns the response <b>ARRAY</b>, otherwise returns <b>FALSE</b>.
     */
    public function denyContract($cid)
    {
        if (!$this->checkAccessToken()) {
            return false;
        }

        $cid = (int)$cid;
        if ($cid <= 0) {
            $this->setError('NO_CID_SET');
            return false;
        }

        return $this->write([
            "contracts" => [
                "_cid" => $cid,
                "_action" => "deny"
            ]
        ]);
    }

    /**
     * Approves the Contract.
     *
     * @param int|string $cid
     * The Contract's ID
     * @param string $address
     * Payment address (optional)
     * @return bool|array If everything went good it returns the response <b>ARRAY</b>, otherwise returns <b>FALSE</b>.
     */
    public function approveContract($cid, $address = "")
    {
        if (!$this->checkAccessToken()) {
            return false;
        }

        $cid = (int)$cid;
        if ($cid <= 0) {
            $this->setError('NO_CID_SET');
            return false;
        }

        return $this->write([
            "contracts" => [
                "_cid" => $cid,
                "_action" => "approve",
                "_address" => $address
            ]
        ]);
    }

    /**
     * Denies the Contract as middleman.
     *
     * @param int|string $cid
     * The Contract's ID
     * @return bool|array If everything went good it returns the response <b>ARRAY</b>, otherwise returns <b>FALSE</b>.
     */
    public function middlemanDenyContract($cid)
    {
        if (!$this->checkAccessToken()) {
            return false;
        }

        $cid = (int)$cid;
        if ($cid <= 0) {
            $this->setError('NO_CID_SET');
            return false;
        }

        return $this->write([
            "contracts" => [
                "_cid" => $cid,
                "_action" => "middleman_deny"
            ]
        ]);
    }

    /**
     * Approves the Contract as middleman.
     *
     * @param int|string $cid
     * The Contract's ID
     * @return bool|array If everything went good it returns the response <b>ARRAY</b>, otherwise returns <b>FALSE</b>.
     */
    public function middlemanApproveContract($cid)
    {
        if (!$this->checkAccessToken()) {
            return false;
        }

        $cid = (int)$cid;
        if ($cid <= 0) {
            $this->setError('NO_CID_SET');
            return false;
        }

        return $this->write([
            "contracts" => [
                "_cid" => $cid,
                "_action" => "middleman_approve"
            ]
        ]);
    }

    /**
     * Cancel the Contract as Vendor.
     *
     * @param int|string $cid
     * The Contract's ID
     * @return bool|array If everything went good it returns the response <b>ARRAY</b>, otherwise returns <b>FALSE</b>.
     */
    public function vendorCancelContract($cid)
    {
        if (!$this->checkAccessToken()) {
            return false;
        }

        $cid = (int)$cid;
        if ($cid <= 0) {
            $this->setError('NO_CID_SET');
            return false;
        }

        return $this->write([
            "contracts" => [
                "_cid" => $cid,
                "_action" => "vendor_cancel"
            ]
        ]);
    }

    /**
     * Cancels the Contract.
     * 
     * @param int|string $cid
     * The Contract's ID
     * @return bool|array If everything went good it returns the response <b>ARRAY</b>, otherwise returns <b>FALSE</b>.
     */
    public function cancelContract($cid)
    {
        if (!$this->checkAccessToken()) {
            return false;
        }

        $cid = (int)$cid;
        if ($cid <= 0) {
            $this->setError('NO_CID_SET');
            return false;
        }

        return $this->write([
            "contracts" => [
                "_cid" => $cid,
                "_action" => "cancel"
            ]
        ]);
    }

    /**
     * Completes the Contract.
     * 
     * @param int|string $cid
     * The Contract's ID
     * @param string $txn
     * TXN (optional)
     * @return bool|array If everything went good it returns the response <b>ARRAY</b>, otherwise returns <b>FALSE</b>.
     */
    public function completeContract($cid, $txn = "")
    {
        if (!$this->checkAccessToken()) {
            return false;
        }

        $cid = (int)$cid;
        if ($cid <= 0) {
            $this->setError('NO_CID_SET');
            return false;
        }

        return $this->write([
            "contracts" => [
                "_cid" => $cid,
                "_action" => "complete",
                "_address" => $txn
            ]
        ]);
    }
}
