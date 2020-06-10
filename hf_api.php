<?php
/**
 * HF API
 * Easily connect to and use HF API v2
 *
 * by Xerotic
 *
 */
 

class HF_API {
	
	
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
	 *
	 * @constructor method
	 */
	function __construct() {
		$this->changeState();
	}
	
	
	/**
	 *
	 * @return null
	 */
	function setClientID($client_id) {
		$this->client_id = $client_id;
	}
	
	
	/**
	 *
	 * @return null
	 */
	function setSecretKey($secret_key) {
		$this->secret_key = $secret_key;
	}
	
	
	/**
	 *
	 * @return string
	 */
	function getAccessToken() {
		return $this->access_token;
	}
	
	
	/**
	 *
	 * @return string
	 */
	function setAccessToken($access_token) {
		$this->access_token = preg_replace("/[^A-Za-z0-9]/", "", $access_token); 
	}
	
	
	/**
	 *
	 * @return null
	 */
	function checkAccessToken() {
		if(!$this->access_token) {
			$this->setError('ACCESS_TOKEN_NOT_SET');
			return false;
		}
		
		return true;
	}
	
	
	/**
	 *
	 * @return string
	 */
	function getUID() {
		return $this->uid;
	}
	
	
	/**
	 *
	 * @return null
	 */
	function setError($error) {
		$this->errors[] = $error;
	}
	
	
	/**
	 *
	 * @return array
	 */
	function getErrors() {
		return $this->errors;
	}
	
	
	/**
	 *
	 * @return string
	 */
	function changeState() {
		$this->state = substr(str_shuffle(MD5(microtime())), 0, 12);
		
		return $this->state;
	}
	
	
	/**
	 *
	 * @return null
	 */
	function setState($state) {
		$this->state = preg_replace("/[^A-Za-z0-9]/", "", $state); 
	}
	
	
	/**
	 *
	 * @return string
	 */
	function getState() {
		return $this->state;
	}
	
	
	/**
	 *
	 * @
	 */
	function sendCurl($url, $post_fields, $http_headers=[]) {
		$ch = curl_init();
		
		curl_setopt($ch, CURLOPT_URL, $url);
		curl_setopt($ch, CURLOPT_POST, 1);
		curl_setopt($ch, CURLOPT_POSTFIELDS, $post_fields);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
		curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 0);
		curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
		
		if($http_headers) {
			curl_setopt($ch, CURLOPT_HTTPHEADER, $http_headers);
		}
		
		$response = curl_exec($ch);
		
		curl_close($ch);
		
		return $response;
	}
	
	
	/**
	 *
	 * @
	 */
	function startAuth() {
		if(!$this->client_id) {
			$this->setError('CLIENT_ID_NOT_SET');
			return false;
		}
		
		header("Location: {$this->authorize_url}?response_type=code&client_id={$this->client_id}&state={$this->state}");
		exit;
	}
	
	
	/**
	 *
	 * @
	 */
	function finishAuth($state="") {
		$state = preg_replace("/[^A-Za-z0-9]/", "", $state);
		
		$input = array_change_key_case($_GET, CASE_LOWER);

		$code = preg_replace("/[^A-Za-z0-9]/", "", $input['code']);
		
		if($state && trim($input['state']) != trim($state)) {
			$this->setError('INVALID_STATE');
			return false;
		}
		
		if(!$code) {
			$this->setError('INVALID_CODE');
			return false;
		}
		
		if(!$this->client_id) {
			$this->setError('CLIENT_ID_NOT_SET');
			return false;
		}
		
		if(!$this->secret_key) {
			$this->setError('SECRET_KEY_NOT_SET');
			return false;
		}

		$response = $this->sendCurl($this->authorize_url, [
			'grant_type' => "authorization_code",
			'client_id' => $this->client_id,
			'client_secret' => $this->secret_key,
			'code' => $code
		]);
		
		if(empty($response)) {
			$this->setError('BAD_RESPONSE_FROM_HF_OR_CURL_ERROR');
			return false;
		}
		
		try {
			$response = json_decode($response, true);
		} catch(Exception $e) {
			$this->setError('BAD_RESPONSE_FROM_HF');
			return false;
		}
		
		if(array_key_exists("success", $response) && $response['success'] == false) {
			if(array_key_exists("message", $response)) {
				$this->setError($response['message']);
			} else {
				$this->setError('BAD_RESPONSE_FROM_HF');
			}
			return false;
		}
		
		if(!array_key_exists("access_token", $response)) {
			$this->setError('BAD_RESPONSE_FROM_HF');
			return false;
		}
		
		$this->access_token = $response['access_token'];
		$this->uid = $response['uid'];
		
		return true;
	}

	
	/**
	 *
	 * @
	 */
	function read($asks) {
		if(!$this->checkAccessToken()) {
			return;
		}
		
		if(!$asks) {
			$this->setError('NO_DATA_REQUESTED');
			return false;
		}
		
		$response = $this->sendCurl($this->read_url, [
			'asks' => json_encode($asks)
		], ["Authorization: Bearer {$this->access_token}"]);
		
		if(empty($response)) {
			$this->setError('BAD_RESPONSE_FROM_HF_OR_CURL_ERROR');
			return false;
		}
		
		try {
			$response = json_decode($response, true);
		} catch(Exception $e) {
			$this->setError('BAD_RESPONSE_FROM_HF');
			return false;
		}
		
		if(array_key_exists("success", $response) && $response['success'] == false) {
			if(array_key_exists("message", $response)) {
				$this->setError($response['message']);
			} else {
				$this->setError('BAD_RESPONSE_FROM_HF');
			}
			return false;
		}
		
		return $response;
	}
	
	
	/**
	 *
	 * @
	 */
	function write($asks) {
		if(!$this->checkAccessToken()) {
			return;
		}
		
		if(!$asks) {
			$this->setError('NO_DATA_REQUESTED');
			return false;
		}
		
		$response = $this->sendCurl($this->write_url, [
			'asks' => json_encode($asks)
		], ["Authorization: Bearer {$this->access_token}"]);
		
		if(empty($response)) {
			$this->setError('BAD_RESPONSE_FROM_HF_OR_CURL_ERROR');
			return false;
		}
		
		try {
			$response = json_decode($response, true);
		} catch(Exception $e) {
			$this->setError('BAD_RESPONSE_FROM_HF');
			return false;
		}
		
		if(!is_array($response)) {
			$response = [];
		}
		
		if(array_key_exists("success", $response) && $response['success'] == false) {
			if(array_key_exists("message", $response)) {
				$this->setError($response['message']);
			} else {
				$this->setError('BAD_RESPONSE_FROM_HF');
			}
			return false;
		}
		
		return $response;
	}
	
	
	/**
	 *
	 * @
	 */
	function makePost($tid, $message) {
		if(!$this->checkAccessToken()) {
			return;
		}
		
		$tid = (int)$tid;
		if($tid < 0) {
			$this->setError('NO_TID_SET');
			return false;
		}
		
		if(!$message || mb_strlen($message) < 3) {
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
	 *
	 * @
	 */
	function makeThread($fid, $subject, $message) {
		if(!$this->checkAccessToken()) {
			return;
		}
		
		$fid = (int)$fid;
		if($fid < 0) {
			$this->setError('NO_FID_SET');
			return false;
		}
		
		if(!$subject || mb_strlen($subject) < 3) {
			$this->setError('NO_SUBJECT_SET');
			return false;
		}
		
		if(!$message || mb_strlen($message) < 3) {
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
	 *
	 * @
	 */
	function sendBytes($uid, $amount, $reason="", $pid=0) {
		if(!$this->checkAccessToken()) {
			return;
		}
		
		$uid = (int)$uid;
		if($uid <= 0) {
			$this->setError('NO_UID_SET');
			return false;
		}
		
		$amount = (int)$amount;
		if($amount <= 0) {
			$this->setError('NO_AMOUNT_SET');
			return false;
		}
		
		if($reason && mb_strlen($reason) > 192) {
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
	 *
	 * @
	 */
	function vaultBalance() {
		if(!$this->checkAccessToken()) {
			return;
		}
		
		$read_vault = $this->read([
			"me" => [
				"vault" => true
			]
		]);
		
		if(!is_array($read_vault) || !array_key_exists('me', $read_vault) || !is_array($read_vault['me']) || !array_key_exists('vault', $read_vault['me'])) {
			return 0;
		} 
		
		return (int)$read_vault['me']['vault'];
	}
	
	
	/**
	 *
	 * @
	 */
	function vaultDeposit($amount) {
		if(!$this->checkAccessToken()) {
			return;
		}
		
		$amount = (int)$amount;
		if($amount <= 0) {
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
	 *
	 * @
	 */
	function vaultWithdraw($amount) {
		if(!$this->checkAccessToken()) {
			return;
		}
		
		$amount = (int)$amount;
		if($amount <= 0) {
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
	 *
	 * @
	 */
	function newContract($ask) {
		if(!$this->checkAccessToken()) {
			return;
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
		
		if($data['_uid'] <= 0) {
			$this->setError('NO_UID_SET_IN_DATA_ARRAY');
			return false;
		}
		
		if(!$data['_position']) {
			$this->setError('NO_POSITION_SET_IN_DATA_ARRAY');
			return false;
		}
		
		if(!$data['_terms']) {
			$this->setError('NO_TERMS_SET_IN_DATA_ARRAY');
			return false;
		}
		
		$write = [
			"contracts" => [
				"_action" => "new"
			]
		];
		
		foreach($data as $key => $field) {
			$write['contracts'][$key] = $field;
		}
		
		return $this->write($write);
	}
	
	
	/**
	 *
	 * @
	 */
	function undoContract($cid) {
		if(!$this->checkAccessToken()) {
			return;
		}
		
		$cid = (int)$cid;
		if($cid <= 0) {
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
	 *
	 * @
	 */
	function denyContract($cid) {
		if(!$this->checkAccessToken()) {
			return;
		}
		
		$cid = (int)$cid;
		if($cid <= 0) {
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
	 *
	 * @
	 */
	function approveContract($cid, $address="") {
		if(!$this->checkAccessToken()) {
			return;
		}
		
		$cid = (int)$cid;
		if($cid <= 0) {
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
	 *
	 * @
	 */
	function middlemanDenyContract($cid) {
		if(!$this->checkAccessToken()) {
			return;
		}
		
		$cid = (int)$cid;
		if($cid <= 0) {
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
	 *
	 * @
	 */
	function middlemanApproveContract($cid) {
		if(!$this->checkAccessToken()) {
			return;
		}
		
		$cid = (int)$cid;
		if($cid <= 0) {
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
	 *
	 * @
	 */
	function vendorCancelContract($cid) {
		if(!$this->checkAccessToken()) {
			return;
		}
		
		$cid = (int)$cid;
		if($cid <= 0) {
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
	 *
	 * @
	 */
	function cancelContract($cid) {
		if(!$this->checkAccessToken()) {
			return;
		}
		
		$cid = (int)$cid;
		if($cid <= 0) {
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
	 *
	 * @
	 */
	function completeContract($cid, $txn="") {
		if(!$this->checkAccessToken()) {
			return;
		}
		
		$cid = (int)$cid;
		if($cid <= 0) {
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
