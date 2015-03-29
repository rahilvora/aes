<?php

require_once('Sbox.php');

class key_aes{

	/*
		File handler pointer for reading
		data from either /dev/random or 
		/dev/urandom
	 */
	private $randomFileHandler;

	/* 
		Storing the AES keys in Hex 
		format as a Single-dimension array
	*/ 
	private $aes_key_bytes;

	/*
		Storing the AES keys in a word 
		format where each word is 32 bits 
	 */
	public $aes_key_words;

	/*
		Storing the AES keys in Matrix form
		as shown in the actual AES algo
	 */
	private $aes_matrix;

	// The key size of AES - 128, 192, 256
	private $aes_key_size;

	/*
		The expanded key size which could be
		44 Words (128 bit key size)
		52 Words (192 bit key size)
		60 Words (256 bit key size)
		Each Word is of 32 Bit ....
	 */
	public $aes_key_expanded;

	/**
	 * [gen_aes_key_hex Key Generation function .. this is
	 * the main function that generates the Key and it could
	 * be of 128 or 192 or 256 Bit key]
	 * @param  integer $key_size [Key size ..]
	 */
	public function gen_aes_key_hex($key_size=128){

		$this->aes_key_size = $key_size;

		if(is_readable('/dev/urandom')){
			$this->randomFileHandler = fopen('/dev/urandom', 'r');
			if($this->randomFileHandler === false)
				throw new Exception('/dev/urandom is readble but can\'t get a file handler with fopen, please check the code.');
		}

		$aes_key_size = $key_size/8;
		$cmd = "dd if=/dev/urandom bs=1 count=$aes_key_size 2>/dev/null | hexdump -v -e '\"%02X\"' ";
		exec($cmd, $this->aes_key_bytes);

		if(strlen($this->aes_key_bytes[0]) != ($key_size/4)){
			sleep(5);
			$this->gen_aes_key_hex($key_size);
		}

		$this->display_aes_key_matrix($this->aes_key_bytes[0]);
	}	

	/**
	 * [get_aes_key Returns the generated AES key not
	 * the expanded one ....]
	 * @return [String] [AES key of 128 or 192 or 256 Bit]
	 */
	public function get_aes_key(){
		if($this->aes_key_bytes === null)
			$this->gen_aes_key_hex();

		return $this->aes_key_bytes[0];
	}

	/**
	 * [aes_key_hexToWord Converts the AES keys into
	 * 32 bit Words which is then used for Key expansion]
	 * @return [String] [32 Bit AES Key]
	 */
	public function aes_key_hexToWord(){
		for($i=0; $i<($this->aes_key_size/32); $i++)
			$this->aes_key_words[0][$i] = $this->aes_matrix[0][$i].$this->aes_matrix[1][$i].$this->aes_matrix[2][$i].$this->aes_matrix[3][$i];

		return $this->aes_key_words;
	}

	/**
	 * [display_aes_key_matrix Displays the AES in matrix]
	 */
	public function display_aes_key_matrix($tmp_aes_key){

		if(!empty($this->aes_matrix))
			return $this->aes_matrix;

		$key_pos=0;

		for($i=0; $i<($this->aes_key_size/32); $i++){
			
			$this->aes_matrix[0][$i] = $tmp_aes_key[$key_pos].$tmp_aes_key[++$key_pos];
			$key_pos++;

			$this->aes_matrix[1][$i] = $tmp_aes_key[$key_pos].$tmp_aes_key[++$key_pos];
			$key_pos++;

			$this->aes_matrix[2][$i] = $tmp_aes_key[$key_pos].$tmp_aes_key[++$key_pos];
			$key_pos++;

			$this->aes_matrix[3][$i] = $tmp_aes_key[$key_pos].$tmp_aes_key[++$key_pos];
			$key_pos++;
		}
		return $this->aes_matrix;
	}

	/**
	 * [g This function is a part of AES key which is called
	 * during the Key Expansion process.]
	 */
	public function g($aes_key_word, $roundNo=1){

		/*
			As a part of g(), you'll need to 
			shift the AES Word $aes_key_word by 1 to left
		 */
		$tmp_aes_key_words = $aes_key_word;

		// var_dump($tmp_aes_key_words);

		$tmp_aes_key_words_split = str_split($tmp_aes_key_words, 2);
		$tmp_aes_key_words = $tmp_aes_key_words_split[1].$tmp_aes_key_words_split[2].$tmp_aes_key_words_split[3].$tmp_aes_key_words_split[0];

		// var_dump($tmp_aes_key_words);
		/*
			Now as a part of the function g(),
			you need to subsitute the value of 
			Words to SBox ....
		 */		
		$tmp_aes_key_words_new = $this->key_to_sBox($tmp_aes_key_words);

		// var_dump($tmp_aes_key_words_new);

		/*
			Now a Round Constant Matrix is needed
			so pass the round no you are in and then
			expect an array back from it....
		 */
		$tmp_round_matrix = $this->get_rCon($roundNo);

		// var_dump($tmp_round_matrix);

		/*
			Now we have the Left Shifted + S-Box matrix of the Key
			and finally we also have the Round Constant Matrix
			so let's finish this up by XORing the Two matrix
			together and getting the answer back ....
		 */
		$g_val = $this->xor_operation($tmp_aes_key_words_new, $tmp_round_matrix);

		return $g_val;
	}

	/**
	 * [key_to_sBox Subsitute the Key by using the S-Box]
	 * @param  [String] $key [the key used for subsitution]
	 * @return [String]      [Subsituted key]
	 */
	public function key_to_sBox($key){

		$sBox_ref = new Sbox;
		$tmp = str_split($key);
		$tmp_sKey = "";
		// $maxCtr = ($this->aes_key_size)/16;
		unset($tmp_sKey);

		for ($i=0,$j=0; $i < 8; $i+=2,$j++) { 
			
			$sBox_key_pos = ( (hexdec($tmp[$i])) *16) + hexdec($tmp[$i+1]);
			$val = dechex($sBox_ref->get_sBox($sBox_key_pos));
			
			if(strlen($val) == 1)
				$tmp_sKey .= '0'.$val;
			else
				$tmp_sKey .= $val;					
		}	
		
		return $tmp_sKey;
	}

	/**
	 * [get_rCon Returns the Round Constant matrix based on the Round No]
	 * @param  [Int] $roundNo [Round No.]
	 * @return [Array]          [Matrix that has the Round Constant]
	 */
	public function get_rCon($roundNo){
		$r_con = array('0', '01', '02', '04', '08', '10', '20', '40', '80', '1B', '36');
		$r_con_matrix = $r_con[$roundNo].'000000';
		return $r_con_matrix;
	}

	/**
	 * [xor_operation Performs XOR operation on the two arguments
	 * It needs the arguments to be in HEX value ]
	 * @param  [String] $var1 [Hex value]
	 * @param  [String] $var2 [Hex value]
	 * @return [String]       [Hex answer to XOR]
	 */
	public function xor_operation($var1, $var2){
		$var1_dec = hexdec($var1);
		$var2_dec = hexdec($var2);

		$xor_result = dechex($var1_dec^$var2_dec);

		if(strlen($xor_result) == 8)
			return $xor_result;

		$padding = "";
		$padding_count = 8 - strlen($xor_result);

		for($iteration=1; $iteration<=$padding_count; $iteration++)
			$padding .= "0";

		return $padding.$xor_result;
	}

	/**
	 * [key_expansion Key expansion function which will take
	 * 4 Words of 32 Bit each for 128 bit key and generates
	 * more 40 Words on top of it...]
	 * @param  [String] $aes_key [4 Words of 32 bit each ..]
	 * @return [String]          [Expanded key]
	 */
	public function key_expansion($aes_key){
		
		/*
			First copy the first 4 words
			in the new expanded key var.
		 */
		$word_col = $this->aes_key_size/32;
		for ($i=0; $i < $word_col; $i++) { 
			$this->aes_key_expanded[$i] = $aes_key[$i];	
		}
		
		// var_dump($this->aes_key_expanded);	

		if($this->aes_key_size == 128)
			$key_expansion_iteration = 10;
		else if($this->aes_key_size == 192)
			$key_expansion_iteration = 12;
		else
			$key_expansion_iteration = 14;

		/*
			First I need to pass the last Word
			from the array to function g()
			which is used to generate the 
			first Word of the 4 words array
		 */
		for ($iteration=1; $iteration <= $key_expansion_iteration; $iteration++) { 

			$g_word = $this->g(end($this->aes_key_expanded), $iteration);
			
			$offset = ($iteration-1)*($this->aes_key_size/32);

			if($this->aes_key_size == 128){

				$first_word = $this->xor_operation($this->aes_key_expanded[$offset], $g_word);
				$second_word = 	$this->xor_operation($this->aes_key_expanded[$offset+1], $first_word);
				$third_word = $this->xor_operation($this->aes_key_expanded[$offset+2], $second_word);
				$fourth_word = $this->xor_operation($this->aes_key_expanded[$offset+3], $third_word);

				$this->aes_key_expanded[$offset+4] = strtoupper($first_word);
				$this->aes_key_expanded[$offset+5] = strtoupper($second_word);
				$this->aes_key_expanded[$offset+6] = strtoupper($third_word);
				$this->aes_key_expanded[$offset+7] = strtoupper($fourth_word);		
			}
			
			else if($this->aes_key_size == 192){

				$first_word = $this->xor_operation($this->aes_key_expanded[$offset], $g_word);
				$second_word = 	$this->xor_operation($this->aes_key_expanded[$offset+1], $first_word);
				$third_word = $this->xor_operation($this->aes_key_expanded[$offset+2], $second_word);
				$fourth_word = $this->xor_operation($this->aes_key_expanded[$offset+3], $third_word);
				$fifth_word = $this->xor_operation($this->aes_key_expanded[$offset+4], $fourth_word);
				$sixth_word = $this->xor_operation($this->aes_key_expanded[$offset+5], $fifth_word);

				$this->aes_key_expanded[$offset+6] = strtoupper($first_word);
				$this->aes_key_expanded[$offset+7] = strtoupper($second_word);
				$this->aes_key_expanded[$offset+8] = strtoupper($third_word);
				$this->aes_key_expanded[$offset+9] = strtoupper($fourth_word);
				$this->aes_key_expanded[$offset+10] = strtoupper($fifth_word);
				$this->aes_key_expanded[$offset+11] = strtoupper($sixth_word);			
			}
				
			else{
				
				$first_word = $this->xor_operation($this->aes_key_expanded[$offset], $g_word);
				$second_word = 	$this->xor_operation($this->aes_key_expanded[$offset+1], $first_word);
				$third_word = $this->xor_operation($this->aes_key_expanded[$offset+2], $second_word);
				$fourth_word = $this->xor_operation($this->aes_key_expanded[$offset+3], $third_word);
				$fifth_word = $this->xor_operation($this->aes_key_expanded[$offset+4], $fourth_word);
				$sixth_word = $this->xor_operation($this->aes_key_expanded[$offset+5], $fifth_word);
				$seventh_word = $this->xor_operation($this->aes_key_expanded[$offset+6], $sixth_word);
				$eight_word = $this->xor_operation($this->aes_key_expanded[$offset+7], $seventh_word);

				$this->aes_key_expanded[$offset+8] = strtoupper($first_word);
				$this->aes_key_expanded[$offset+9] = strtoupper($second_word);
				$this->aes_key_expanded[$offset+10] = strtoupper($third_word);
				$this->aes_key_expanded[$offset+11] = strtoupper($fourth_word);		
				$this->aes_key_expanded[$offset+12] = strtoupper($fifth_word);
				$this->aes_key_expanded[$offset+13] = strtoupper($sixth_word);
				$this->aes_key_expanded[$offset+14] = strtoupper($seventh_word);
				$this->aes_key_expanded[$offset+15] = strtoupper($eight_word);
			}
		}		
	}

}

$key = new key_aes;
$key->gen_aes_key_hex(128);
echo 'Old Key <br/>';
var_dump($key->get_aes_key());
echo '<br/> <br/> New Key';
var_dump($key->display_aes_key_matrix($key->get_aes_key()));
var_dump($key->aes_key_hexToWord());

$key->key_expansion($key->aes_key_words[0]);

var_dump($key->aes_key_expanded);



