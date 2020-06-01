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
	private $errors;
	private $state;
	private $authorize_url = "https://hackforums.net/api/v2/authorize";
	private $read_url = "https://hackforums.net/api/v2/read";
	private $write_url = "https://hackforums.net/api/v2/write";
 
 
	 /**
	 *
	 * constructor method
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
	 * @return null
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
	 * @return bool
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

		$ch = curl_init();
		
		curl_setopt($ch, CURLOPT_URL, $this->authorize_url);
		curl_setopt($ch, CURLOPT_POST, 1);
		curl_setopt($ch, CURLOPT_POSTFIELDS, [
			'grant_type' => "authorization_code",
			'client_id' => $this->client_id,
			'client_secret' => $this->secret_key,
			'code' => $code
		]);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
		curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 0);
		curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
		
		$response = curl_exec($ch);
		
		curl_close($ch);
		
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
	 * @return bool
	 */
	function read($asks) {
		if(!$this->access_token) {
			$this->setError('ACCESS_TOKEN_NOT_SET');
			return false;
		}
		
		if(!$asks) {
			$this->setError('NO_DATA_REQUESTED');
			return false;
		}

		$ch = curl_init();
		
		curl_setopt($ch, CURLOPT_URL, $this->read_url);
		curl_setopt($ch, CURLOPT_POST, 1);
		curl_setopt($ch, CURLOPT_POSTFIELDS, [
			'asks' => json_encode($asks)
		]);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
		curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 0);
		curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
		curl_setopt($ch, CURLOPT_HTTPHEADER, ["Authorization: Bearer {$this->access_token}"]);
		
		$response = curl_exec($ch);
		
		curl_close($ch);
		
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
	
	
	
}
