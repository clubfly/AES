<?php
/***
 * Key Sizes:
 * 16 bytes = 128 bit encryption
 * 24 bytes = 192 bit encryption
 * 32 bytes = 256 bit encryption
 * Padding Formats:
 * ANSI_X.923
 * ISO_10126
 * PKCS7
 * BIT
 * ZERO
 * -- Example Usage:
 * $message = " Test AES";
 * $key = array(0x70, 0x2F, 0x17, 0x7F, 0x6C, 0x3A, 0x22, 0x11,
 *              0x3F, 0x44, 0x5A, 0x66, 0x77, 0x1A, 0x12, 0x1C );
 * $iv  = array(0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31,
 *              0x38, 0x37, 0x36, 0x35, 0x34, 0x33,0x32, 0x31);
 * $padding          = "PKCS7"; // Padding Formats list => ANSI_X.923,ISO_10126,PKCS7,BIT,ZERO
 * $mode             = "cbc"; // mode list => ecb,cfb,cbc,nofb,ofb
 * $AES              = new AES_Encryption($key, $iv, $padding, $mode);
 * $encrypted        = $AES->encrypt($message);
 * $decrypted        = $AES->decrypt($encrypted);
 **/
require_once(dirname(__FILE__)."/padCrypt.php");
class AESEngine{
  private $key, $initVector, $mode, $cipher, $encryption = null;
  private $allowed_bits = array(128, 192, 256);
  private $allowed_modes = array('ecb', 'cfb', 'cbc', 'nofb', 'ofb');
  private $vector_modes = array('cbc','cfb','ofb');
  private $allowed_paddings = array(
                                    'ANSI_X.923' => 'ANSI_X923',
                                    'ISO_10126'	 => 'ISO_10126',
                                    'PKCS7'		 => 'PKCS7',
                                    'BIT'		 => 'BIT',
                                    'ZERO'		 => 'ZERO',
                                   );
  private $padCrypt_url = 'http://dev.strategystar.net/2011/10/php-cryptography-padding-ansi-x-923-iso-10126-pkcs7-bit-zero/';
  public function __construct($key, $initVector='', 
                              $padding='ZERO', $mode='cbc'){
    $mode = strtolower($mode);
    $padding = strtoupper($padding);
    if(!class_exists('padCrypt')){
      exit('The padCrypt class must be loaded: '.$this->padCrypt_url);
    }
    if(!function_exists('mcrypt_module_open')){
      exit('The mcrypt extension must be loaded.');
    }
    $initVector = $this->setBinToASCII($initVector);
    if(strlen($initVector) != 16 && 
       in_array($mode, $this->vector_modes)){
      exit('InitVector is supposed to be 16 bytes for CBC, CFB, NOFB, and OFB modes.');
    } elseif(!in_array($mode, $this->vector_modes) && !empty($initVector)){
      exit('The specified encryption mode does not use an initialization vector. 
            You should pass an empty string, zero, FALSE, or NULL.');
    }
    $key = $this->setBinToASCII($key);
    $this->encryption = strlen($key)*8;
    if(!in_array($this->encryption, $this->allowed_bits)){
      exit('Key must be either 16, 24, or 32 bytes in length for 128,192,and 256 bit');
    }
    $this->key = $key;
    $this->initVector = $initVector;
    if(!in_array($mode, $this->allowed_modes)){
      exit('Mode must be one of the following: '.implode(', ', $this->allowed_modes));
    }
    if(!array_key_exists($padding, $this->allowed_paddings)){
      exit('The $padding must be one of the following: '.
           implode(',', $this->allowed_paddings));
    }
    $this->mode = $mode;
    $this->padding = $padding;
    $this->cipher = mcrypt_module_open('rijndael-128', '', $this->mode, '');
    $this->block_size = mcrypt_get_block_size('rijndael-128', $this->mode);
  }
  public function setBinToASCII($bin){
    $str = null;
    foreach ($bin as $val){
      $str .= pack("C*",$val);
    }
    return $str;
  }
  public function encrypt($text){
    mcrypt_generic_init($this->cipher,$this->key,$this->initVector);
	$encrypted_text = mcrypt_generic($this->cipher,
                                     $this->pad($text,$this->block_size));
    mcrypt_generic_deinit($this->cipher);
    return strtoupper(bin2hex($encrypted_text));
  }
  public function decrypt($text){
    $text = $this->hex2bin(strtolower($text));
    mcrypt_generic_init($this->cipher,$this->key,$this->initVector);
    $decrypted_text = mdecrypt_generic($this->cipher,$text);
    mcrypt_generic_deinit($this->cipher);
    return $this->unpad($decrypted_text);
  }
  public function hex2bin($hex_string) {
    return pack('H*',$hex_string);
  }
  public function getConfiguration(){
    return array(
                 'key' 			=> $this->key,
                 'init_vector'  => $this->initVector,
                 'padding' 		=> $this->padding,
                 'mode'         => $this->mode,
                 'encryption'	=> $this->encryption . ' Bit',
                 'block_size'	=> $this->block_size
                );
  }
  private function pad($text, $block_size){
    return call_user_func_array(array('padCrypt', 
                                      'pad_'.$this->allowed_paddings[$this->padding]),
                                      array($text, $block_size)
                               );
  }
  private function unpad($text){
    return call_user_func_array(array('padCrypt', 
                                      'unpad_'.$this->allowed_paddings[$this->padding]),
                                      array($text));
  }
  public function __destruct(){
    mcrypt_module_close($this->cipher);
  }
}
/*$key = array(0x70, 0x2F, 0x17, 0x7F, 0x6C, 0x3A, 0x22, 0x11, 
             0x3F, 0x44, 0x5A, 0x66, 0x77, 0x1A, 0x12, 0x1C );
$iv = array(0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 
            0x38, 0x37, 0x36, 0x35, 0x34, 0x33,0x32, 0x31);
$message = "1234";
$AES = new AESEngine($key,$iv,"PKCS7","cbc");
$encrypted = $AES->encrypt($message);
$decrypted = $AES->decrypt($encrypted);
echo "encrypted: ".$encrypted;
echo "\n";
echo "decrypted: ".$decrypted;
echo "\n";*/
?>
