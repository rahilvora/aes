<?php

class key_aes{

	private $randomFileHandler;
	private $aes_key_bytes;
	private $aes_key_words;
	private $aes_matrix;

	public function gen_aes_key_hex($key_size=128){

		if(is_readable('/dev/random')){
			$this->randomFileHandler = fopen('/dev/urandom', 'r');
			if($this->randomFileHandler === false)
				throw new Exception('/dev/random is readble but can\'t get a file handler with fopen, please check the code.');
		}

		$aes_key_size = $key_size/8;
		$cmd = "dd if=/dev/urandom bs=1 count=$aes_key_size 2>/dev/null | hexdump -v -e '\"%02X\"' ";
		exec($cmd, $this->aes_key_bytes);

		$this->display_aes_key_matrix($this->aes_key_bytes[0]);
	}	

	public function get_aes_key(){
		if($this->aes_key_bytes === null)
			$this->gen_aes_key_hex();

		return $this->aes_key_bytes[0];
	}

	public function aes_key_hexToWord(){
		return ($this->aes_key_words = str_split($this->aes_key_bytes[0], 8));
	}

	public function display_aes_key_matrix($tmp_aes_key){

		if(!empty($this->aes_matrix))
			return $this->aes_matrix;

		$key_pos=0;
		for($i=0; $i<4; $i++){
			
			$this->aes_matrix[0][$i] = $tmp_aes_key[$key_pos]."".$tmp_aes_key[++$key_pos];
			$key_pos++;

			$this->aes_matrix[1][$i] = $tmp_aes_key[$key_pos]."".$tmp_aes_key[++$key_pos];
			$key_pos++;

			$this->aes_matrix[2][$i] = $tmp_aes_key[$key_pos]."".$tmp_aes_key[++$key_pos];
			$key_pos++;

			$this->aes_matrix[3][$i] = $tmp_aes_key[$key_pos]."".$tmp_aes_key[++$key_pos];
			$key_pos++;
			$j++;
		}
		return $this->aes_matrix;
	}

	public function display_aes_key(){

	}
}

$key = new key_aes;
$key->gen_aes_key_hex();
echo 'Old Key <br/>';
echo $key->get_aes_key();
echo '<br/> <br/> New Key';
var_dump($key->display_aes_key_matrix($key->get_aes_key()));


