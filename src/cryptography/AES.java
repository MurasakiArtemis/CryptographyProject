package cryptography;

public class AES {
static byte[][] state;
	
/**************************** DATA TYPES ****************************/
static int AES_128_ROUNDS=10;
static int AES_192_ROUNDS=12;
static int AES_256_ROUNDS=14;

/*********************** FUNCTION DECLARATIONS **********************/
//void ccm_prepare_first_ctr_blk(BYTE counter[], const BYTE nonce[], int nonce_len, int payload_len_store_size);
//void ccm_prepare_first_format_blk(BYTE buf[], int assoc_len, int payload_len, int payload_len_store_size, int mac_len, const BYTE nonce[], int nonce_len);
//void ccm_format_assoc_data(BYTE buf[], int *end_of_buf, const BYTE assoc[], int assoc_len);
//void ccm_format_payload_data(BYTE buf[], int *end_of_buf, const BYTE payload[], int payload_len);

	/**************************** VARIABLES *****************************/
	// This is the specified AES SBox. To look up a substitution value, put the first
	// nibble in the first index (row) and the second nibble in the second index (column).
	static byte aes_sbox[][] = { 
			{(byte)0x63,(byte)0x7C,(byte)0x77,(byte)0x7B,(byte)0xF2,(byte)0x6B,(byte)0x6F,(byte)0xC5,(byte)0x30,(byte)0x01,(byte)0x67,(byte)0x2B,(byte)0xFE,(byte)0xD7,(byte)0xAB,(byte)0x76},
			{(byte)0xCA,(byte)0x82,(byte)0xC9,(byte)0x7D,(byte)0xFA,(byte)0x59,(byte)0x47,(byte)0xF0,(byte)0xAD,(byte)0xD4,(byte)0xA2,(byte)0xAF,(byte)0x9C,(byte)0xA4,(byte)0x72,(byte)0xC0},
			{(byte)0xB7,(byte)0xFD,(byte)0x93,(byte)0x26,(byte)0x36,(byte)0x3F,(byte)0xF7,(byte)0xCC,(byte)0x34,(byte)0xA5,(byte)0xE5,(byte)0xF1,(byte)0x71,(byte)0xD8,(byte)0x31,(byte)0x15},
			{(byte)0x04,(byte)0xC7,(byte)0x23,(byte)0xC3,(byte)0x18,(byte)0x96,(byte)0x05,(byte)0x9A,(byte)0x07,(byte)0x12,(byte)0x80,(byte)0xE2,(byte)0xEB,(byte)0x27,(byte)0xB2,(byte)0x75},
			{(byte)0x09,(byte)0x83,(byte)0x2C,(byte)0x1A,(byte)0x1B,(byte)0x6E,(byte)0x5A,(byte)0xA0,(byte)0x52,(byte)0x3B,(byte)0xD6,(byte)0xB3,(byte)0x29,(byte)0xE3,(byte)0x2F,(byte)0x84},
			{(byte)0x53,(byte)0xD1,(byte)0x00,(byte)0xED,(byte)0x20,(byte)0xFC,(byte)0xB1,(byte)0x5B,(byte)0x6A,(byte)0xCB,(byte)0xBE,(byte)0x39,(byte)0x4A,(byte)0x4C,(byte)0x58,(byte)0xCF},
			{(byte)0xD0,(byte)0xEF,(byte)0xAA,(byte)0xFB,(byte)0x43,(byte)0x4D,(byte)0x33,(byte)0x85,(byte)0x45,(byte)0xF9,(byte)0x02,(byte)0x7F,(byte)0x50,(byte)0x3C,(byte)0x9F,(byte)0xA8},
			{(byte)0x51,(byte)0xA3,(byte)0x40,(byte)0x8F,(byte)0x92,(byte)0x9D,(byte)0x38,(byte)0xF5,(byte)0xBC,(byte)0xB6,(byte)0xDA,(byte)0x21,(byte)0x10,(byte)0xFF,(byte)0xF3,(byte)0xD2},
			{(byte)0xCD,(byte)0x0C,(byte)0x13,(byte)0xEC,(byte)0x5F,(byte)0x97,(byte)0x44,(byte)0x17,(byte)0xC4,(byte)0xA7,(byte)0x7E,(byte)0x3D,(byte)0x64,(byte)0x5D,(byte)0x19,(byte)0x73},
			{(byte)0x60,(byte)0x81,(byte)0x4F,(byte)0xDC,(byte)0x22,(byte)0x2A,(byte)0x90,(byte)0x88,(byte)0x46,(byte)0xEE,(byte)0xB8,(byte)0x14,(byte)0xDE,(byte)0x5E,(byte)0x0B,(byte)0xDB},
			{(byte)0xE0,(byte)0x32,(byte)0x3A,(byte)0x0A,(byte)0x49,(byte)0x06,(byte)0x24,(byte)0x5C,(byte)0xC2,(byte)0xD3,(byte)0xAC,(byte)0x62,(byte)0x91,(byte)0x95,(byte)0xE4,(byte)0x79},
			{(byte)0xE7,(byte)0xC8,(byte)0x37,(byte)0x6D,(byte)0x8D,(byte)0xD5,(byte)0x4E,(byte)0xA9,(byte)0x6C,(byte)0x56,(byte)0xF4,(byte)0xEA,(byte)0x65,(byte)0x7A,(byte)0xAE,(byte)0x08},
			{(byte)0xBA,(byte)0x78,(byte)0x25,(byte)0x2E,(byte)0x1C,(byte)0xA6,(byte)0xB4,(byte)0xC6,(byte)0xE8,(byte)0xDD,(byte)0x74,(byte)0x1F,(byte)0x4B,(byte)0xBD,(byte)0x8B,(byte)0x8A},
			{(byte)0x70,(byte)0x3E,(byte)0xB5,(byte)0x66,(byte)0x48,(byte)0x03,(byte)0xF6,(byte)0x0E,(byte)0x61,(byte)0x35,(byte)0x57,(byte)0xB9,(byte)0x86,(byte)0xC1,(byte)0x1D,(byte)0x9E},
			{(byte)0xE1,(byte)0xF8,(byte)0x98,(byte)0x11,(byte)0x69,(byte)0xD9,(byte)0x8E,(byte)0x94,(byte)0x9B,(byte)0x1E,(byte)0x87,(byte)0xE9,(byte)0xCE,(byte)0x55,(byte)0x28,(byte)0xDF},
			{(byte)0x8C,(byte)0xA1,(byte)0x89,(byte)0x0D,(byte)0xBF,(byte)0xE6,(byte)0x42,(byte)0x68,(byte)0x41,(byte)0x99,(byte)0x2D,(byte)0x0F,(byte)0xB0,(byte)0x54,(byte)0xBB,(byte)0x16}
	};

	static byte aes_invsbox[][] = {
			{(byte)0x52,(byte)0x09,(byte)0x6A,(byte)0xD5,(byte)0x30,(byte)0x36,(byte)0xA5,(byte)0x38,(byte)0xBF,(byte)0x40,(byte)0xA3,(byte)0x9E,(byte)0x81,(byte)0xF3,(byte)0xD7,(byte)0xFB},
			{(byte)0x7C,(byte)0xE3,(byte)0x39,(byte)0x82,(byte)0x9B,(byte)0x2F,(byte)0xFF,(byte)0x87,(byte)0x34,(byte)0x8E,(byte)0x43,(byte)0x44,(byte)0xC4,(byte)0xDE,(byte)0xE9,(byte)0xCB},
			{(byte)0x54,(byte)0x7B,(byte)0x94,(byte)0x32,(byte)0xA6,(byte)0xC2,(byte)0x23,(byte)0x3D,(byte)0xEE,(byte)0x4C,(byte)0x95,(byte)0x0B,(byte)0x42,(byte)0xFA,(byte)0xC3,(byte)0x4E},
			{(byte)0x08,(byte)0x2E,(byte)0xA1,(byte)0x66,(byte)0x28,(byte)0xD9,(byte)0x24,(byte)0xB2,(byte)0x76,(byte)0x5B,(byte)0xA2,(byte)0x49,(byte)0x6D,(byte)0x8B,(byte)0xD1,(byte)0x25},
			{(byte)0x72,(byte)0xF8,(byte)0xF6,(byte)0x64,(byte)0x86,(byte)0x68,(byte)0x98,(byte)0x16,(byte)0xD4,(byte)0xA4,(byte)0x5C,(byte)0xCC,(byte)0x5D,(byte)0x65,(byte)0xB6,(byte)0x92},
			{(byte)0x6C,(byte)0x70,(byte)0x48,(byte)0x50,(byte)0xFD,(byte)0xED,(byte)0xB9,(byte)0xDA,(byte)0x5E,(byte)0x15,(byte)0x46,(byte)0x57,(byte)0xA7,(byte)0x8D,(byte)0x9D,(byte)0x84},
			{(byte)0x90,(byte)0xD8,(byte)0xAB,(byte)0x00,(byte)0x8C,(byte)0xBC,(byte)0xD3,(byte)0x0A,(byte)0xF7,(byte)0xE4,(byte)0x58,(byte)0x05,(byte)0xB8,(byte)0xB3,(byte)0x45,(byte)0x06},
			{(byte)0xD0,(byte)0x2C,(byte)0x1E,(byte)0x8F,(byte)0xCA,(byte)0x3F,(byte)0x0F,(byte)0x02,(byte)0xC1,(byte)0xAF,(byte)0xBD,(byte)0x03,(byte)0x01,(byte)0x13,(byte)0x8A,(byte)0x6B},
			{(byte)0x3A,(byte)0x91,(byte)0x11,(byte)0x41,(byte)0x4F,(byte)0x67,(byte)0xDC,(byte)0xEA,(byte)0x97,(byte)0xF2,(byte)0xCF,(byte)0xCE,(byte)0xF0,(byte)0xB4,(byte)0xE6,(byte)0x73},
			{(byte)0x96,(byte)0xAC,(byte)0x74,(byte)0x22,(byte)0xE7,(byte)0xAD,(byte)0x35,(byte)0x85,(byte)0xE2,(byte)0xF9,(byte)0x37,(byte)0xE8,(byte)0x1C,(byte)0x75,(byte)0xDF,(byte)0x6E},
			{(byte)0x47,(byte)0xF1,(byte)0x1A,(byte)0x71,(byte)0x1D,(byte)0x29,(byte)0xC5,(byte)0x89,(byte)0x6F,(byte)0xB7,(byte)0x62,(byte)0x0E,(byte)0xAA,(byte)0x18,(byte)0xBE,(byte)0x1B},
			{(byte)0xFC,(byte)0x56,(byte)0x3E,(byte)0x4B,(byte)0xC6,(byte)0xD2,(byte)0x79,(byte)0x20,(byte)0x9A,(byte)0xDB,(byte)0xC0,(byte)0xFE,(byte)0x78,(byte)0xCD,(byte)0x5A,(byte)0xF4},
			{(byte)0x1F,(byte)0xDD,(byte)0xA8,(byte)0x33,(byte)0x88,(byte)0x07,(byte)0xC7,(byte)0x31,(byte)0xB1,(byte)0x12,(byte)0x10,(byte)0x59,(byte)0x27,(byte)0x80,(byte)0xEC,(byte)0x5F},
			{(byte)0x60,(byte)0x51,(byte)0x7F,(byte)0xA9,(byte)0x19,(byte)0xB5,(byte)0x4A,(byte)0x0D,(byte)0x2D,(byte)0xE5,(byte)0x7A,(byte)0x9F,(byte)0x93,(byte)0xC9,(byte)0x9C,(byte)0xEF},
			{(byte)0xA0,(byte)0xE0,(byte)0x3B,(byte)0x4D,(byte)0xAE,(byte)0x2A,(byte)0xF5,(byte)0xB0,(byte)0xC8,(byte)0xEB,(byte)0xBB,(byte)0x3C,(byte)0x83,(byte)0x53,(byte)0x99,(byte)0x61},
			{(byte)0x17,(byte)0x2B,(byte)0x04,(byte)0x7E,(byte)0xBA,(byte)0x77,(byte)0xD6,(byte)0x26,(byte)0xE1,(byte)0x69,(byte)0x14,(byte)0x63,(byte)0x55,(byte)0x21,(byte)0x0C,(byte)0x7D}
	};

	// This table stores pre-calculated values for all possible GF(2^8) calculations.This
	// table is only used by the (Inv)MixColumns steps.
	// USAGE: The second index (column) is the coefficient of multiplication. Only 7 different
	// coefficients are used: 0x01, 0x02, 0x03, 0x09, 0x0b, 0x0d, 0x0e, but multiplication by
	// 1 is negligible leaving only 6 coefficients. Each column of the table is devoted to one
	// of these coefficients, in the ascending order of value, from values 0x00 to 0xFF.
	static byte gf_mul[][] = {
			{(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00},{(byte)0x02,(byte)0x03,(byte)0x09,(byte)0x0b,(byte)0x0d,(byte)0x0e},
			{(byte)0x04,(byte)0x06,(byte)0x12,(byte)0x16,(byte)0x1a,(byte)0x1c},{(byte)0x06,(byte)0x05,(byte)0x1b,(byte)0x1d,(byte)0x17,(byte)0x12},
			{(byte)0x08,(byte)0x0c,(byte)0x24,(byte)0x2c,(byte)0x34,(byte)0x38},{(byte)0x0a,(byte)0x0f,(byte)0x2d,(byte)0x27,(byte)0x39,(byte)0x36},
			{(byte)0x0c,(byte)0x0a,(byte)0x36,(byte)0x3a,(byte)0x2e,(byte)0x24},{(byte)0x0e,(byte)0x09,(byte)0x3f,(byte)0x31,(byte)0x23,(byte)0x2a},
			{(byte)0x10,(byte)0x18,(byte)0x48,(byte)0x58,(byte)0x68,(byte)0x70},{(byte)0x12,(byte)0x1b,(byte)0x41,(byte)0x53,(byte)0x65,(byte)0x7e},
			{(byte)0x14,(byte)0x1e,(byte)0x5a,(byte)0x4e,(byte)0x72,(byte)0x6c},{(byte)0x16,(byte)0x1d,(byte)0x53,(byte)0x45,(byte)0x7f,(byte)0x62},
			{(byte)0x18,(byte)0x14,(byte)0x6c,(byte)0x74,(byte)0x5c,(byte)0x48},{(byte)0x1a,(byte)0x17,(byte)0x65,(byte)0x7f,(byte)0x51,(byte)0x46},
			{(byte)0x1c,(byte)0x12,(byte)0x7e,(byte)0x62,(byte)0x46,(byte)0x54},{(byte)0x1e,(byte)0x11,(byte)0x77,(byte)0x69,(byte)0x4b,(byte)0x5a},
			{(byte)0x20,(byte)0x30,(byte)0x90,(byte)0xb0,(byte)0xd0,(byte)0xe0},{(byte)0x22,(byte)0x33,(byte)0x99,(byte)0xbb,(byte)0xdd,(byte)0xee},
			{(byte)0x24,(byte)0x36,(byte)0x82,(byte)0xa6,(byte)0xca,(byte)0xfc},{(byte)0x26,(byte)0x35,(byte)0x8b,(byte)0xad,(byte)0xc7,(byte)0xf2},
			{(byte)0x28,(byte)0x3c,(byte)0xb4,(byte)0x9c,(byte)0xe4,(byte)0xd8},{(byte)0x2a,(byte)0x3f,(byte)0xbd,(byte)0x97,(byte)0xe9,(byte)0xd6},
			{(byte)0x2c,(byte)0x3a,(byte)0xa6,(byte)0x8a,(byte)0xfe,(byte)0xc4},{(byte)0x2e,(byte)0x39,(byte)0xaf,(byte)0x81,(byte)0xf3,(byte)0xca},
			{(byte)0x30,(byte)0x28,(byte)0xd8,(byte)0xe8,(byte)0xb8,(byte)0x90},{(byte)0x32,(byte)0x2b,(byte)0xd1,(byte)0xe3,(byte)0xb5,(byte)0x9e},
			{(byte)0x34,(byte)0x2e,(byte)0xca,(byte)0xfe,(byte)0xa2,(byte)0x8c},{(byte)0x36,(byte)0x2d,(byte)0xc3,(byte)0xf5,(byte)0xaf,(byte)0x82},
			{(byte)0x38,(byte)0x24,(byte)0xfc,(byte)0xc4,(byte)0x8c,(byte)0xa8},{(byte)0x3a,(byte)0x27,(byte)0xf5,(byte)0xcf,(byte)0x81,(byte)0xa6},
			{(byte)0x3c,(byte)0x22,(byte)0xee,(byte)0xd2,(byte)0x96,(byte)0xb4},{(byte)0x3e,(byte)0x21,(byte)0xe7,(byte)0xd9,(byte)0x9b,(byte)0xba},
			{(byte)0x40,(byte)0x60,(byte)0x3b,(byte)0x7b,(byte)0xbb,(byte)0xdb},{(byte)0x42,(byte)0x63,(byte)0x32,(byte)0x70,(byte)0xb6,(byte)0xd5},
			{(byte)0x44,(byte)0x66,(byte)0x29,(byte)0x6d,(byte)0xa1,(byte)0xc7},{(byte)0x46,(byte)0x65,(byte)0x20,(byte)0x66,(byte)0xac,(byte)0xc9},
			{(byte)0x48,(byte)0x6c,(byte)0x1f,(byte)0x57,(byte)0x8f,(byte)0xe3},{(byte)0x4a,(byte)0x6f,(byte)0x16,(byte)0x5c,(byte)0x82,(byte)0xed},
			{(byte)0x4c,(byte)0x6a,(byte)0x0d,(byte)0x41,(byte)0x95,(byte)0xff},{(byte)0x4e,(byte)0x69,(byte)0x04,(byte)0x4a,(byte)0x98,(byte)0xf1},
			{(byte)0x50,(byte)0x78,(byte)0x73,(byte)0x23,(byte)0xd3,(byte)0xab},{(byte)0x52,(byte)0x7b,(byte)0x7a,(byte)0x28,(byte)0xde,(byte)0xa5},
			{(byte)0x54,(byte)0x7e,(byte)0x61,(byte)0x35,(byte)0xc9,(byte)0xb7},{(byte)0x56,(byte)0x7d,(byte)0x68,(byte)0x3e,(byte)0xc4,(byte)0xb9},
			{(byte)0x58,(byte)0x74,(byte)0x57,(byte)0x0f,(byte)0xe7,(byte)0x93},{(byte)0x5a,(byte)0x77,(byte)0x5e,(byte)0x04,(byte)0xea,(byte)0x9d},
			{(byte)0x5c,(byte)0x72,(byte)0x45,(byte)0x19,(byte)0xfd,(byte)0x8f},{(byte)0x5e,(byte)0x71,(byte)0x4c,(byte)0x12,(byte)0xf0,(byte)0x81},
			{(byte)0x60,(byte)0x50,(byte)0xab,(byte)0xcb,(byte)0x6b,(byte)0x3b},{(byte)0x62,(byte)0x53,(byte)0xa2,(byte)0xc0,(byte)0x66,(byte)0x35},
			{(byte)0x64,(byte)0x56,(byte)0xb9,(byte)0xdd,(byte)0x71,(byte)0x27},{(byte)0x66,(byte)0x55,(byte)0xb0,(byte)0xd6,(byte)0x7c,(byte)0x29},
			{(byte)0x68,(byte)0x5c,(byte)0x8f,(byte)0xe7,(byte)0x5f,(byte)0x03},{(byte)0x6a,(byte)0x5f,(byte)0x86,(byte)0xec,(byte)0x52,(byte)0x0d},
			{(byte)0x6c,(byte)0x5a,(byte)0x9d,(byte)0xf1,(byte)0x45,(byte)0x1f},{(byte)0x6e,(byte)0x59,(byte)0x94,(byte)0xfa,(byte)0x48,(byte)0x11},
			{(byte)0x70,(byte)0x48,(byte)0xe3,(byte)0x93,(byte)0x03,(byte)0x4b},{(byte)0x72,(byte)0x4b,(byte)0xea,(byte)0x98,(byte)0x0e,(byte)0x45},
			{(byte)0x74,(byte)0x4e,(byte)0xf1,(byte)0x85,(byte)0x19,(byte)0x57},{(byte)0x76,(byte)0x4d,(byte)0xf8,(byte)0x8e,(byte)0x14,(byte)0x59},
			{(byte)0x78,(byte)0x44,(byte)0xc7,(byte)0xbf,(byte)0x37,(byte)0x73},{(byte)0x7a,(byte)0x47,(byte)0xce,(byte)0xb4,(byte)0x3a,(byte)0x7d},
			{(byte)0x7c,(byte)0x42,(byte)0xd5,(byte)0xa9,(byte)0x2d,(byte)0x6f},{(byte)0x7e,(byte)0x41,(byte)0xdc,(byte)0xa2,(byte)0x20,(byte)0x61},
			{(byte)0x80,(byte)0xc0,(byte)0x76,(byte)0xf6,(byte)0x6d,(byte)0xad},{(byte)0x82,(byte)0xc3,(byte)0x7f,(byte)0xfd,(byte)0x60,(byte)0xa3},
			{(byte)0x84,(byte)0xc6,(byte)0x64,(byte)0xe0,(byte)0x77,(byte)0xb1},{(byte)0x86,(byte)0xc5,(byte)0x6d,(byte)0xeb,(byte)0x7a,(byte)0xbf},
			{(byte)0x88,(byte)0xcc,(byte)0x52,(byte)0xda,(byte)0x59,(byte)0x95},{(byte)0x8a,(byte)0xcf,(byte)0x5b,(byte)0xd1,(byte)0x54,(byte)0x9b},
			{(byte)0x8c,(byte)0xca,(byte)0x40,(byte)0xcc,(byte)0x43,(byte)0x89},{(byte)0x8e,(byte)0xc9,(byte)0x49,(byte)0xc7,(byte)0x4e,(byte)0x87},
			{(byte)0x90,(byte)0xd8,(byte)0x3e,(byte)0xae,(byte)0x05,(byte)0xdd},{(byte)0x92,(byte)0xdb,(byte)0x37,(byte)0xa5,(byte)0x08,(byte)0xd3},
			{(byte)0x94,(byte)0xde,(byte)0x2c,(byte)0xb8,(byte)0x1f,(byte)0xc1},{(byte)0x96,(byte)0xdd,(byte)0x25,(byte)0xb3,(byte)0x12,(byte)0xcf},
			{(byte)0x98,(byte)0xd4,(byte)0x1a,(byte)0x82,(byte)0x31,(byte)0xe5},{(byte)0x9a,(byte)0xd7,(byte)0x13,(byte)0x89,(byte)0x3c,(byte)0xeb},
			{(byte)0x9c,(byte)0xd2,(byte)0x08,(byte)0x94,(byte)0x2b,(byte)0xf9},{(byte)0x9e,(byte)0xd1,(byte)0x01,(byte)0x9f,(byte)0x26,(byte)0xf7},
			{(byte)0xa0,(byte)0xf0,(byte)0xe6,(byte)0x46,(byte)0xbd,(byte)0x4d},{(byte)0xa2,(byte)0xf3,(byte)0xef,(byte)0x4d,(byte)0xb0,(byte)0x43},
			{(byte)0xa4,(byte)0xf6,(byte)0xf4,(byte)0x50,(byte)0xa7,(byte)0x51},{(byte)0xa6,(byte)0xf5,(byte)0xfd,(byte)0x5b,(byte)0xaa,(byte)0x5f},
			{(byte)0xa8,(byte)0xfc,(byte)0xc2,(byte)0x6a,(byte)0x89,(byte)0x75},{(byte)0xaa,(byte)0xff,(byte)0xcb,(byte)0x61,(byte)0x84,(byte)0x7b},
			{(byte)0xac,(byte)0xfa,(byte)0xd0,(byte)0x7c,(byte)0x93,(byte)0x69},{(byte)0xae,(byte)0xf9,(byte)0xd9,(byte)0x77,(byte)0x9e,(byte)0x67},
			{(byte)0xb0,(byte)0xe8,(byte)0xae,(byte)0x1e,(byte)0xd5,(byte)0x3d},{(byte)0xb2,(byte)0xeb,(byte)0xa7,(byte)0x15,(byte)0xd8,(byte)0x33},
			{(byte)0xb4,(byte)0xee,(byte)0xbc,(byte)0x08,(byte)0xcf,(byte)0x21},{(byte)0xb6,(byte)0xed,(byte)0xb5,(byte)0x03,(byte)0xc2,(byte)0x2f},
			{(byte)0xb8,(byte)0xe4,(byte)0x8a,(byte)0x32,(byte)0xe1,(byte)0x05},{(byte)0xba,(byte)0xe7,(byte)0x83,(byte)0x39,(byte)0xec,(byte)0x0b},
			{(byte)0xbc,(byte)0xe2,(byte)0x98,(byte)0x24,(byte)0xfb,(byte)0x19},{(byte)0xbe,(byte)0xe1,(byte)0x91,(byte)0x2f,(byte)0xf6,(byte)0x17},
			{(byte)0xc0,(byte)0xa0,(byte)0x4d,(byte)0x8d,(byte)0xd6,(byte)0x76},{(byte)0xc2,(byte)0xa3,(byte)0x44,(byte)0x86,(byte)0xdb,(byte)0x78},
			{(byte)0xc4,(byte)0xa6,(byte)0x5f,(byte)0x9b,(byte)0xcc,(byte)0x6a},{(byte)0xc6,(byte)0xa5,(byte)0x56,(byte)0x90,(byte)0xc1,(byte)0x64},
			{(byte)0xc8,(byte)0xac,(byte)0x69,(byte)0xa1,(byte)0xe2,(byte)0x4e},{(byte)0xca,(byte)0xaf,(byte)0x60,(byte)0xaa,(byte)0xef,(byte)0x40},
			{(byte)0xcc,(byte)0xaa,(byte)0x7b,(byte)0xb7,(byte)0xf8,(byte)0x52},{(byte)0xce,(byte)0xa9,(byte)0x72,(byte)0xbc,(byte)0xf5,(byte)0x5c},
			{(byte)0xd0,(byte)0xb8,(byte)0x05,(byte)0xd5,(byte)0xbe,(byte)0x06},{(byte)0xd2,(byte)0xbb,(byte)0x0c,(byte)0xde,(byte)0xb3,(byte)0x08},
			{(byte)0xd4,(byte)0xbe,(byte)0x17,(byte)0xc3,(byte)0xa4,(byte)0x1a},{(byte)0xd6,(byte)0xbd,(byte)0x1e,(byte)0xc8,(byte)0xa9,(byte)0x14},
			{(byte)0xd8,(byte)0xb4,(byte)0x21,(byte)0xf9,(byte)0x8a,(byte)0x3e},{(byte)0xda,(byte)0xb7,(byte)0x28,(byte)0xf2,(byte)0x87,(byte)0x30},
			{(byte)0xdc,(byte)0xb2,(byte)0x33,(byte)0xef,(byte)0x90,(byte)0x22},{(byte)0xde,(byte)0xb1,(byte)0x3a,(byte)0xe4,(byte)0x9d,(byte)0x2c},
			{(byte)0xe0,(byte)0x90,(byte)0xdd,(byte)0x3d,(byte)0x06,(byte)0x96},{(byte)0xe2,(byte)0x93,(byte)0xd4,(byte)0x36,(byte)0x0b,(byte)0x98},
			{(byte)0xe4,(byte)0x96,(byte)0xcf,(byte)0x2b,(byte)0x1c,(byte)0x8a},{(byte)0xe6,(byte)0x95,(byte)0xc6,(byte)0x20,(byte)0x11,(byte)0x84},
			{(byte)0xe8,(byte)0x9c,(byte)0xf9,(byte)0x11,(byte)0x32,(byte)0xae},{(byte)0xea,(byte)0x9f,(byte)0xf0,(byte)0x1a,(byte)0x3f,(byte)0xa0},
			{(byte)0xec,(byte)0x9a,(byte)0xeb,(byte)0x07,(byte)0x28,(byte)0xb2},{(byte)0xee,(byte)0x99,(byte)0xe2,(byte)0x0c,(byte)0x25,(byte)0xbc},
			{(byte)0xf0,(byte)0x88,(byte)0x95,(byte)0x65,(byte)0x6e,(byte)0xe6},{(byte)0xf2,(byte)0x8b,(byte)0x9c,(byte)0x6e,(byte)0x63,(byte)0xe8},
			{(byte)0xf4,(byte)0x8e,(byte)0x87,(byte)0x73,(byte)0x74,(byte)0xfa},{(byte)0xf6,(byte)0x8d,(byte)0x8e,(byte)0x78,(byte)0x79,(byte)0xf4},
			{(byte)0xf8,(byte)0x84,(byte)0xb1,(byte)0x49,(byte)0x5a,(byte)0xde},{(byte)0xfa,(byte)0x87,(byte)0xb8,(byte)0x42,(byte)0x57,(byte)0xd0},
			{(byte)0xfc,(byte)0x82,(byte)0xa3,(byte)0x5f,(byte)0x40,(byte)0xc2},{(byte)0xfe,(byte)0x81,(byte)0xaa,(byte)0x54,(byte)0x4d,(byte)0xcc},
			{(byte)0x1b,(byte)0x9b,(byte)0xec,(byte)0xf7,(byte)0xda,(byte)0x41},{(byte)0x19,(byte)0x98,(byte)0xe5,(byte)0xfc,(byte)0xd7,(byte)0x4f},
			{(byte)0x1f,(byte)0x9d,(byte)0xfe,(byte)0xe1,(byte)0xc0,(byte)0x5d},{(byte)0x1d,(byte)0x9e,(byte)0xf7,(byte)0xea,(byte)0xcd,(byte)0x53},
			{(byte)0x13,(byte)0x97,(byte)0xc8,(byte)0xdb,(byte)0xee,(byte)0x79},{(byte)0x11,(byte)0x94,(byte)0xc1,(byte)0xd0,(byte)0xe3,(byte)0x77},
			{(byte)0x17,(byte)0x91,(byte)0xda,(byte)0xcd,(byte)0xf4,(byte)0x65},{(byte)0x15,(byte)0x92,(byte)0xd3,(byte)0xc6,(byte)0xf9,(byte)0x6b},
			{(byte)0x0b,(byte)0x83,(byte)0xa4,(byte)0xaf,(byte)0xb2,(byte)0x31},{(byte)0x09,(byte)0x80,(byte)0xad,(byte)0xa4,(byte)0xbf,(byte)0x3f},
			{(byte)0x0f,(byte)0x85,(byte)0xb6,(byte)0xb9,(byte)0xa8,(byte)0x2d},{(byte)0x0d,(byte)0x86,(byte)0xbf,(byte)0xb2,(byte)0xa5,(byte)0x23},
			{(byte)0x03,(byte)0x8f,(byte)0x80,(byte)0x83,(byte)0x86,(byte)0x09},{(byte)0x01,(byte)0x8c,(byte)0x89,(byte)0x88,(byte)0x8b,(byte)0x07},
			{(byte)0x07,(byte)0x89,(byte)0x92,(byte)0x95,(byte)0x9c,(byte)0x15},{(byte)0x05,(byte)0x8a,(byte)0x9b,(byte)0x9e,(byte)0x91,(byte)0x1b},
			{(byte)0x3b,(byte)0xab,(byte)0x7c,(byte)0x47,(byte)0x0a,(byte)0xa1},{(byte)0x39,(byte)0xa8,(byte)0x75,(byte)0x4c,(byte)0x07,(byte)0xaf},
			{(byte)0x3f,(byte)0xad,(byte)0x6e,(byte)0x51,(byte)0x10,(byte)0xbd},{(byte)0x3d,(byte)0xae,(byte)0x67,(byte)0x5a,(byte)0x1d,(byte)0xb3},
			{(byte)0x33,(byte)0xa7,(byte)0x58,(byte)0x6b,(byte)0x3e,(byte)0x99},{(byte)0x31,(byte)0xa4,(byte)0x51,(byte)0x60,(byte)0x33,(byte)0x97},
			{(byte)0x37,(byte)0xa1,(byte)0x4a,(byte)0x7d,(byte)0x24,(byte)0x85},{(byte)0x35,(byte)0xa2,(byte)0x43,(byte)0x76,(byte)0x29,(byte)0x8b},
			{(byte)0x2b,(byte)0xb3,(byte)0x34,(byte)0x1f,(byte)0x62,(byte)0xd1},{(byte)0x29,(byte)0xb0,(byte)0x3d,(byte)0x14,(byte)0x6f,(byte)0xdf},
			{(byte)0x2f,(byte)0xb5,(byte)0x26,(byte)0x09,(byte)0x78,(byte)0xcd},{(byte)0x2d,(byte)0xb6,(byte)0x2f,(byte)0x02,(byte)0x75,(byte)0xc3},
			{(byte)0x23,(byte)0xbf,(byte)0x10,(byte)0x33,(byte)0x56,(byte)0xe9},{(byte)0x21,(byte)0xbc,(byte)0x19,(byte)0x38,(byte)0x5b,(byte)0xe7},
			{(byte)0x27,(byte)0xb9,(byte)0x02,(byte)0x25,(byte)0x4c,(byte)0xf5},{(byte)0x25,(byte)0xba,(byte)0x0b,(byte)0x2e,(byte)0x41,(byte)0xfb},
			{(byte)0x5b,(byte)0xfb,(byte)0xd7,(byte)0x8c,(byte)0x61,(byte)0x9a},{(byte)0x59,(byte)0xf8,(byte)0xde,(byte)0x87,(byte)0x6c,(byte)0x94},
			{(byte)0x5f,(byte)0xfd,(byte)0xc5,(byte)0x9a,(byte)0x7b,(byte)0x86},{(byte)0x5d,(byte)0xfe,(byte)0xcc,(byte)0x91,(byte)0x76,(byte)0x88},
			{(byte)0x53,(byte)0xf7,(byte)0xf3,(byte)0xa0,(byte)0x55,(byte)0xa2},{(byte)0x51,(byte)0xf4,(byte)0xfa,(byte)0xab,(byte)0x58,(byte)0xac},
			{(byte)0x57,(byte)0xf1,(byte)0xe1,(byte)0xb6,(byte)0x4f,(byte)0xbe},{(byte)0x55,(byte)0xf2,(byte)0xe8,(byte)0xbd,(byte)0x42,(byte)0xb0},
			{(byte)0x4b,(byte)0xe3,(byte)0x9f,(byte)0xd4,(byte)0x09,(byte)0xea},{(byte)0x49,(byte)0xe0,(byte)0x96,(byte)0xdf,(byte)0x04,(byte)0xe4},
			{(byte)0x4f,(byte)0xe5,(byte)0x8d,(byte)0xc2,(byte)0x13,(byte)0xf6},{(byte)0x4d,(byte)0xe6,(byte)0x84,(byte)0xc9,(byte)0x1e,(byte)0xf8},
			{(byte)0x43,(byte)0xef,(byte)0xbb,(byte)0xf8,(byte)0x3d,(byte)0xd2},{(byte)0x41,(byte)0xec,(byte)0xb2,(byte)0xf3,(byte)0x30,(byte)0xdc},
			{(byte)0x47,(byte)0xe9,(byte)0xa9,(byte)0xee,(byte)0x27,(byte)0xce},{(byte)0x45,(byte)0xea,(byte)0xa0,(byte)0xe5,(byte)0x2a,(byte)0xc0},
			{(byte)0x7b,(byte)0xcb,(byte)0x47,(byte)0x3c,(byte)0xb1,(byte)0x7a},{(byte)0x79,(byte)0xc8,(byte)0x4e,(byte)0x37,(byte)0xbc,(byte)0x74},
			{(byte)0x7f,(byte)0xcd,(byte)0x55,(byte)0x2a,(byte)0xab,(byte)0x66},{(byte)0x7d,(byte)0xce,(byte)0x5c,(byte)0x21,(byte)0xa6,(byte)0x68},
			{(byte)0x73,(byte)0xc7,(byte)0x63,(byte)0x10,(byte)0x85,(byte)0x42},{(byte)0x71,(byte)0xc4,(byte)0x6a,(byte)0x1b,(byte)0x88,(byte)0x4c},
			{(byte)0x77,(byte)0xc1,(byte)0x71,(byte)0x06,(byte)0x9f,(byte)0x5e},{(byte)0x75,(byte)0xc2,(byte)0x78,(byte)0x0d,(byte)0x92,(byte)0x50},
			{(byte)0x6b,(byte)0xd3,(byte)0x0f,(byte)0x64,(byte)0xd9,(byte)0x0a},{(byte)0x69,(byte)0xd0,(byte)0x06,(byte)0x6f,(byte)0xd4,(byte)0x04},
			{(byte)0x6f,(byte)0xd5,(byte)0x1d,(byte)0x72,(byte)0xc3,(byte)0x16},{(byte)0x6d,(byte)0xd6,(byte)0x14,(byte)0x79,(byte)0xce,(byte)0x18},
			{(byte)0x63,(byte)0xdf,(byte)0x2b,(byte)0x48,(byte)0xed,(byte)0x32},{(byte)0x61,(byte)0xdc,(byte)0x22,(byte)0x43,(byte)0xe0,(byte)0x3c},
			{(byte)0x67,(byte)0xd9,(byte)0x39,(byte)0x5e,(byte)0xf7,(byte)0x2e},{(byte)0x65,(byte)0xda,(byte)0x30,(byte)0x55,(byte)0xfa,(byte)0x20},
			{(byte)0x9b,(byte)0x5b,(byte)0x9a,(byte)0x01,(byte)0xb7,(byte)0xec},{(byte)0x99,(byte)0x58,(byte)0x93,(byte)0x0a,(byte)0xba,(byte)0xe2},
			{(byte)0x9f,(byte)0x5d,(byte)0x88,(byte)0x17,(byte)0xad,(byte)0xf0},{(byte)0x9d,(byte)0x5e,(byte)0x81,(byte)0x1c,(byte)0xa0,(byte)0xfe},
			{(byte)0x93,(byte)0x57,(byte)0xbe,(byte)0x2d,(byte)0x83,(byte)0xd4},{(byte)0x91,(byte)0x54,(byte)0xb7,(byte)0x26,(byte)0x8e,(byte)0xda},
			{(byte)0x97,(byte)0x51,(byte)0xac,(byte)0x3b,(byte)0x99,(byte)0xc8},{(byte)0x95,(byte)0x52,(byte)0xa5,(byte)0x30,(byte)0x94,(byte)0xc6},
			{(byte)0x8b,(byte)0x43,(byte)0xd2,(byte)0x59,(byte)0xdf,(byte)0x9c},{(byte)0x89,(byte)0x40,(byte)0xdb,(byte)0x52,(byte)0xd2,(byte)0x92},
			{(byte)0x8f,(byte)0x45,(byte)0xc0,(byte)0x4f,(byte)0xc5,(byte)0x80},{(byte)0x8d,(byte)0x46,(byte)0xc9,(byte)0x44,(byte)0xc8,(byte)0x8e},
			{(byte)0x83,(byte)0x4f,(byte)0xf6,(byte)0x75,(byte)0xeb,(byte)0xa4},{(byte)0x81,(byte)0x4c,(byte)0xff,(byte)0x7e,(byte)0xe6,(byte)0xaa},
			{(byte)0x87,(byte)0x49,(byte)0xe4,(byte)0x63,(byte)0xf1,(byte)0xb8},{(byte)0x85,(byte)0x4a,(byte)0xed,(byte)0x68,(byte)0xfc,(byte)0xb6},
			{(byte)0xbb,(byte)0x6b,(byte)0x0a,(byte)0xb1,(byte)0x67,(byte)0x0c},{(byte)0xb9,(byte)0x68,(byte)0x03,(byte)0xba,(byte)0x6a,(byte)0x02},
			{(byte)0xbf,(byte)0x6d,(byte)0x18,(byte)0xa7,(byte)0x7d,(byte)0x10},{(byte)0xbd,(byte)0x6e,(byte)0x11,(byte)0xac,(byte)0x70,(byte)0x1e},
			{(byte)0xb3,(byte)0x67,(byte)0x2e,(byte)0x9d,(byte)0x53,(byte)0x34},{(byte)0xb1,(byte)0x64,(byte)0x27,(byte)0x96,(byte)0x5e,(byte)0x3a},
			{(byte)0xb7,(byte)0x61,(byte)0x3c,(byte)0x8b,(byte)0x49,(byte)0x28},{(byte)0xb5,(byte)0x62,(byte)0x35,(byte)0x80,(byte)0x44,(byte)0x26},
			{(byte)0xab,(byte)0x73,(byte)0x42,(byte)0xe9,(byte)0x0f,(byte)0x7c},{(byte)0xa9,(byte)0x70,(byte)0x4b,(byte)0xe2,(byte)0x02,(byte)0x72},
			{(byte)0xaf,(byte)0x75,(byte)0x50,(byte)0xff,(byte)0x15,(byte)0x60},{(byte)0xad,(byte)0x76,(byte)0x59,(byte)0xf4,(byte)0x18,(byte)0x6e},
			{(byte)0xa3,(byte)0x7f,(byte)0x66,(byte)0xc5,(byte)0x3b,(byte)0x44},{(byte)0xa1,(byte)0x7c,(byte)0x6f,(byte)0xce,(byte)0x36,(byte)0x4a},
			{(byte)0xa7,(byte)0x79,(byte)0x74,(byte)0xd3,(byte)0x21,(byte)0x58},{(byte)0xa5,(byte)0x7a,(byte)0x7d,(byte)0xd8,(byte)0x2c,(byte)0x56},
			{(byte)0xdb,(byte)0x3b,(byte)0xa1,(byte)0x7a,(byte)0x0c,(byte)0x37},{(byte)0xd9,(byte)0x38,(byte)0xa8,(byte)0x71,(byte)0x01,(byte)0x39},
			{(byte)0xdf,(byte)0x3d,(byte)0xb3,(byte)0x6c,(byte)0x16,(byte)0x2b},{(byte)0xdd,(byte)0x3e,(byte)0xba,(byte)0x67,(byte)0x1b,(byte)0x25},
			{(byte)0xd3,(byte)0x37,(byte)0x85,(byte)0x56,(byte)0x38,(byte)0x0f},{(byte)0xd1,(byte)0x34,(byte)0x8c,(byte)0x5d,(byte)0x35,(byte)0x01},
			{(byte)0xd7,(byte)0x31,(byte)0x97,(byte)0x40,(byte)0x22,(byte)0x13},{(byte)0xd5,(byte)0x32,(byte)0x9e,(byte)0x4b,(byte)0x2f,(byte)0x1d},
			{(byte)0xcb,(byte)0x23,(byte)0xe9,(byte)0x22,(byte)0x64,(byte)0x47},{(byte)0xc9,(byte)0x20,(byte)0xe0,(byte)0x29,(byte)0x69,(byte)0x49},
			{(byte)0xcf,(byte)0x25,(byte)0xfb,(byte)0x34,(byte)0x7e,(byte)0x5b},{(byte)0xcd,(byte)0x26,(byte)0xf2,(byte)0x3f,(byte)0x73,(byte)0x55},
			{(byte)0xc3,(byte)0x2f,(byte)0xcd,(byte)0x0e,(byte)0x50,(byte)0x7f},{(byte)0xc1,(byte)0x2c,(byte)0xc4,(byte)0x05,(byte)0x5d,(byte)0x71},
			{(byte)0xc7,(byte)0x29,(byte)0xdf,(byte)0x18,(byte)0x4a,(byte)0x63},{(byte)0xc5,(byte)0x2a,(byte)0xd6,(byte)0x13,(byte)0x47,(byte)0x6d},
			{(byte)0xfb,(byte)0x0b,(byte)0x31,(byte)0xca,(byte)0xdc,(byte)0xd7},{(byte)0xf9,(byte)0x08,(byte)0x38,(byte)0xc1,(byte)0xd1,(byte)0xd9},
			{(byte)0xff,(byte)0x0d,(byte)0x23,(byte)0xdc,(byte)0xc6,(byte)0xcb},{(byte)0xfd,(byte)0x0e,(byte)0x2a,(byte)0xd7,(byte)0xcb,(byte)0xc5},
			{(byte)0xf3,(byte)0x07,(byte)0x15,(byte)0xe6,(byte)0xe8,(byte)0xef},{(byte)0xf1,(byte)0x04,(byte)0x1c,(byte)0xed,(byte)0xe5,(byte)0xe1},
			{(byte)0xf7,(byte)0x01,(byte)0x07,(byte)0xf0,(byte)0xf2,(byte)0xf3},{(byte)0xf5,(byte)0x02,(byte)0x0e,(byte)0xfb,(byte)0xff,(byte)0xfd},
			{(byte)0xeb,(byte)0x13,(byte)0x79,(byte)0x92,(byte)0xb4,(byte)0xa7},{(byte)0xe9,(byte)0x10,(byte)0x70,(byte)0x99,(byte)0xb9,(byte)0xa9},
			{(byte)0xef,(byte)0x15,(byte)0x6b,(byte)0x84,(byte)0xae,(byte)0xbb},{(byte)0xed,(byte)0x16,(byte)0x62,(byte)0x8f,(byte)0xa3,(byte)0xb5},
			{(byte)0xe3,(byte)0x1f,(byte)0x5d,(byte)0xbe,(byte)0x80,(byte)0x9f},{(byte)0xe1,(byte)0x1c,(byte)0x54,(byte)0xb5,(byte)0x8d,(byte)0x91},
			{(byte)0xe7,(byte)0x19,(byte)0x4f,(byte)0xa8,(byte)0x9a,(byte)0x83},{(byte)0xe5,(byte)0x1a,(byte)0x46,(byte)0xa3,(byte)0x97,(byte)0x8d}
	};


	public AES()
	{
	this.state=new byte[4][4];
	}
	
	/****************************** MACROS ******************************/
	// The least significant byte of the word is rotated to the end.

	//#define KE_ROTWORD(x) (((x) << 8) | ((x) >> 24))
	private static int KE_ROTWORD(int x)
	{
	return (((x) << 8) | ((x) >> 24));
	}

		
	/*******************
	* AES
	*******************/
	/////////////////
	// KEY EXPANSION
	/////////////////

	// Substitutes a word using the AES S-Box.
	private static int SubWord(int word)
	{
	int result;

	result = (int)aes_sbox[(word >> 4) & 0x0000000F][word & 0x0000000F];
	result += (int)aes_sbox[(word >> 12) & 0x0000000F][(word >> 8) & 0x0000000F] << 8;
	result += (int)aes_sbox[(word >> 20) & 0x0000000F][(word >> 16) & 0x0000000F] << 16;
	result += (int)aes_sbox[(word >> 28) & 0x0000000F][(word >> 24) & 0x0000000F] << 24;
		
	return result;
	}

	// Performs the action of generating the keys that will be used in every round of
	// encryption. "key" is the user-supplied input key, "w" is the output key schedule,
	// "keysize" is the length in bits of "key", must be 128, 192, or 256.
	//void aes_key_setup(const BYTE key[], WORD w[], int keysize)
	int[] aes_key_setup(byte key[], int keysize)
	{
	int Nb=4, Nr=0, Nk=0, idx;
	int temp, Rcon[]={0x01000000,0x02000000,0x04000000,0x08000000,0x10000000,0x20000000,
	                  0x40000000,0x80000000,0x1b000000,0x36000000,0x6c000000,0xd8000000,
	                  0xab000000,0x4d000000,0x9a000000};

		switch (keysize) 
		{
			case 128: Nr = 10; Nk = 4; break;
			case 192: Nr = 12; Nk = 6; break;
			case 256: Nr = 14; Nk = 8; break;
			//default: return;
		}
		
	//Check this XD
	int[] w=new int[Nb * (Nr+1)];

		for (idx=0; idx < Nk; ++idx) 
		{
		w[idx] = ((key[4 * idx]) << 24) | ((key[4 * idx + 1]) << 16) | ((key[4 * idx + 2]) << 8) | ((key[4 * idx + 3]));
		}

		for (idx = Nk; idx < Nb * (Nr+1); ++idx) 
		{	
		temp = w[idx - 1];
		
			if ((idx % Nk) == 0) temp = SubWord(KE_ROTWORD(temp)) ^ Rcon[(idx-1)/Nk];
			else if (Nk > 6 && (idx % Nk) == 4) temp = SubWord(temp);
			
		w[idx] = w[idx-Nk] ^ temp;
		}
		
	return w;
	}

	/////////////////
	// ADD ROUND KEY
	/////////////////

	// Performs the AddRoundKey step. Each round has its own pre-generated 16-byte key in the
	// form of 4 integers (the "w" array). Each integer is XOR'd by one column of the state.
	// Also performs the job of InvAddRoundKey(); since the function is a simple XOR process,
	// it is its own inverse.
	//void AddRoundKey(BYTE state[][4], const WORD w[])
	private static void AddRoundKey(int[] w)
	{
	byte[] subkey=new byte[4];

	// memcpy(subkey,&w[idx],4); // Not accurate for big endian machines
	// Subkey 1
	subkey[0] = (byte)(w[0] >> 24);
	subkey[1] = (byte)(w[0] >> 16);
	subkey[2] = (byte)(w[0] >> 8);
	subkey[3] = (byte)w[0];
	state[0][0] ^= subkey[0];
	state[1][0] ^= subkey[1];
	state[2][0] ^= subkey[2];
	state[3][0] ^= subkey[3];
	// Subkey 2
	subkey[0] = (byte)(w[1] >> 24);
	subkey[1] = (byte)(w[1] >> 16);
	subkey[2] = (byte)(w[1] >> 8);
	subkey[3] = (byte)w[1];
	state[0][1] ^= subkey[0];
	state[1][1] ^= subkey[1];
	state[2][1] ^= subkey[2];
	state[3][1] ^= subkey[3];
	// Subkey 3
	subkey[0] = (byte)(w[2] >> 24);
	subkey[1] = (byte)(w[2] >> 16);
	subkey[2] = (byte)(w[2] >> 8);
	subkey[3] = (byte)w[2];
	state[0][2] ^= subkey[0];
	state[1][2] ^= subkey[1];
	state[2][2] ^= subkey[2];
	state[3][2] ^= subkey[3];
	// Subkey 4
	subkey[0] = (byte)(w[3] >> 24);
	subkey[1] = (byte)(w[3] >> 16);
	subkey[2] = (byte)(w[3] >> 8);
	subkey[3] = (byte)w[3];
	state[0][3] ^= subkey[0];
	state[1][3] ^= subkey[1];
	state[2][3] ^= subkey[2];
	state[3][3] ^= subkey[3];
	}
	
	/////////////////
	// (Inv)SubBytes
	/////////////////

	// Performs the SubBytes step. All bytes in the state are substituted with a
	// pre-calculated value from a lookup table.
	//void SubBytes(BYTE state[][4])
	private static void SubBytes()
	{
		for (int i=0; i<4; i++)
		{
			for (int j=0; j<4; j++){
			int i1=(state[i][j] >> 4)&0x0F;
			int i2=(state[i][j] & 0x0F);
			//System.out.println("i1: "+i1+", i2: "+i2);
			
			state[i][j] = aes_sbox[i1][i2];
			}
		}
		
	/*state[0][0] = aes_sbox[state[0][0] >> 4][state[0][0] & 0x0F];
	state[0][1] = aes_sbox[state[0][1] >> 4][state[0][1] & 0x0F];
	state[0][2] = aes_sbox[state[0][2] >> 4][state[0][2] & 0x0F];
	state[0][3] = aes_sbox[state[0][3] >> 4][state[0][3] & 0x0F];
	state[1][0] = aes_sbox[state[1][0] >> 4][state[1][0] & 0x0F];
	state[1][1] = aes_sbox[state[1][1] >> 4][state[1][1] & 0x0F];
	state[1][2] = aes_sbox[state[1][2] >> 4][state[1][2] & 0x0F];
	state[1][3] = aes_sbox[state[1][3] >> 4][state[1][3] & 0x0F];
	state[2][0] = aes_sbox[state[2][0] >> 4][state[2][0] & 0x0F];
	state[2][1] = aes_sbox[state[2][1] >> 4][state[2][1] & 0x0F];
	state[2][2] = aes_sbox[state[2][2] >> 4][state[2][2] & 0x0F];
	state[2][3] = aes_sbox[state[2][3] >> 4][state[2][3] & 0x0F];
	state[3][0] = aes_sbox[state[3][0] >> 4][state[3][0] & 0x0F];
	state[3][1] = aes_sbox[state[3][1] >> 4][state[3][1] & 0x0F];
	state[3][2] = aes_sbox[state[3][2] >> 4][state[3][2] & 0x0F];
	state[3][3] = aes_sbox[state[3][3] >> 4][state[3][3] & 0x0F];*/
	}

	//void InvSubBytes(BYTE state[][4])
	private static void InvSubBytes()
	{
		for (int i=0; i<4; i++)
		{
			for (int j=0; j<4; j++){
			int i1=(state[i][j] >> 4)&0x0F;
			int i2=(state[i][j] & 0x0F);
			//System.out.println("i1: "+i1+", i2: "+i2);
			
			state[i][j] = aes_invsbox[i1][i2];
			}
		}
	/*state[0][0] = aes_invsbox[state[0][0] >> 4][state[0][0] & 0x0F];
	state[0][1] = aes_invsbox[state[0][1] >> 4][state[0][1] & 0x0F];
	state[0][2] = aes_invsbox[state[0][2] >> 4][state[0][2] & 0x0F];
	state[0][3] = aes_invsbox[state[0][3] >> 4][state[0][3] & 0x0F];
	state[1][0] = aes_invsbox[state[1][0] >> 4][state[1][0] & 0x0F];
	state[1][1] = aes_invsbox[state[1][1] >> 4][state[1][1] & 0x0F];
	state[1][2] = aes_invsbox[state[1][2] >> 4][state[1][2] & 0x0F];
	state[1][3] = aes_invsbox[state[1][3] >> 4][state[1][3] & 0x0F];
	state[2][0] = aes_invsbox[state[2][0] >> 4][state[2][0] & 0x0F];
	state[2][1] = aes_invsbox[state[2][1] >> 4][state[2][1] & 0x0F];
	state[2][2] = aes_invsbox[state[2][2] >> 4][state[2][2] & 0x0F];
	state[2][3] = aes_invsbox[state[2][3] >> 4][state[2][3] & 0x0F];
	state[3][0] = aes_invsbox[state[3][0] >> 4][state[3][0] & 0x0F];
	state[3][1] = aes_invsbox[state[3][1] >> 4][state[3][1] & 0x0F];
	state[3][2] = aes_invsbox[state[3][2] >> 4][state[3][2] & 0x0F];
	state[3][3] = aes_invsbox[state[3][3] >> 4][state[3][3] & 0x0F];*/
	}

	/////////////////
	// (Inv)ShiftRows
	/////////////////

	// Performs the ShiftRows step. All rows are shifted cylindrically to the left.
	//void ShiftRows(BYTE state[][4])
	private static void ShiftRows()
	{
	int t;

	// Shift left by 1
	t = state[1][0];
	state[1][0] = state[1][1];
	state[1][1] = state[1][2];
	state[1][2] = state[1][3];
	state[1][3] = (byte)t;
	// Shift left by 2
	t = state[2][0];
	state[2][0] = state[2][2];
	state[2][2] = (byte)t;
	t = state[2][1];
	state[2][1] = state[2][3];
	state[2][3] = (byte)t;
	// Shift left by 3
	t = state[3][0];
	state[3][0] = state[3][3];
	state[3][3] = state[3][2];
	state[3][2] = state[3][1];
	state[3][1] = (byte)t;
	}

	// All rows are shifted cylindrically to the right.
	//void InvShiftRows(BYTE state[][4])
	private static void InvShiftRows()
	{
	int t;

	// Shift right by 1
	t = state[1][3];
	state[1][3] = state[1][2];
	state[1][2] = state[1][1];
	state[1][1] = state[1][0];
	state[1][0] = (byte)t;
	// Shift right by 2
	t = state[2][3];
	state[2][3] = state[2][1];
	state[2][1] = (byte)t;
	t = state[2][2];
	state[2][2] = state[2][0];
	state[2][0] = (byte)t;
	// Shift right by 3
	t = state[3][3];
	state[3][3] = state[3][0];
	state[3][0] = state[3][1];
	state[3][1] = state[3][2];
	state[3][2] = (byte)t;
	}

	/////////////////
	// (Inv)MixColumns
	/////////////////

	// Performs the MixColums step. The state is multiplied by itself using matrix
	// multiplication in a Galios Field 2^8. All multiplication is pre-computed in a table.
	// Addition is equivilent to XOR. (Must always make a copy of the column as the original
	// values will be destoyed.)
	//void MixColumns(BYTE state[][4])
	private static void MixColumns()
	{
	byte[] col=new byte[4];

	// Column 1
	col[0] = state[0][0];
	col[1] = state[1][0];
	col[2] = state[2][0];
	col[3] = state[3][0];
	
	int i0=col[0]&0xFF;
	int i1=col[1]&0xFF;
	int i2=col[2]&0xFF;
	int i3=col[3]&0xFF;
	
	state[0][0] = gf_mul[i0][0];
	state[0][0] ^= gf_mul[i1][1];
	state[0][0] ^= col[2];
	state[0][0] ^= col[3];
	state[1][0] = col[0];
	state[1][0] ^= gf_mul[i1][0];
	state[1][0] ^= gf_mul[i2][1];
	state[1][0] ^= col[3];
	state[2][0] = col[0];
	state[2][0] ^= col[1];
	state[2][0] ^= gf_mul[i2][0];
	state[2][0] ^= gf_mul[i3][1];
	state[3][0] = gf_mul[i0][1];
	state[3][0] ^= col[1];
	state[3][0] ^= col[2];
	state[3][0] ^= gf_mul[i3][0];
	// Column 2
	col[0] = state[0][1];
	col[1] = state[1][1];
	col[2] = state[2][1];
	col[3] = state[3][1];
	
	i0=col[0]&0xFF;
	i1=col[1]&0xFF;
	i2=col[2]&0xFF;
	i3=col[3]&0xFF;
	
	state[0][1] = gf_mul[i0][0];
	state[0][1] ^= gf_mul[i1][1];
	state[0][1] ^= col[2];
	state[0][1] ^= col[3];
	state[1][1] = col[0];
	state[1][1] ^= gf_mul[i1][0];
	state[1][1] ^= gf_mul[i2][1];
	state[1][1] ^= col[3];
	state[2][1] = col[0];
	state[2][1] ^= col[1];
	state[2][1] ^= gf_mul[i2][0];
	state[2][1] ^= gf_mul[i3][1];
	state[3][1] = gf_mul[i0][1];
	state[3][1] ^= col[1];
	state[3][1] ^= col[2];
	state[3][1] ^= gf_mul[i3][0];
	// Column 3
	col[0] = state[0][2];
	col[1] = state[1][2];
	col[2] = state[2][2];
	col[3] = state[3][2];
	
	i0=col[0]&0xFF;
	i1=col[1]&0xFF;
	i2=col[2]&0xFF;
	i3=col[3]&0xFF;
	
	state[0][2] = gf_mul[i0][0];
	state[0][2] ^= gf_mul[i1][1];
	state[0][2] ^= col[2];
	state[0][2] ^= col[3];
	state[1][2] = col[0];
	state[1][2] ^= gf_mul[i1][0];
	state[1][2] ^= gf_mul[i2][1];
	state[1][2] ^= col[3];
	state[2][2] = col[0];
	state[2][2] ^= col[1];
	state[2][2] ^= gf_mul[i2][0];
	state[2][2] ^= gf_mul[i3][1];
	state[3][2] = gf_mul[i0][1];
	state[3][2] ^= col[1];
	state[3][2] ^= col[2];
	state[3][2] ^= gf_mul[i3][0];
	// Column 4
	col[0] = state[0][3];
	col[1] = state[1][3];
	col[2] = state[2][3];
	col[3] = state[3][3];
	
	i0=col[0]&0xFF;
	i1=col[1]&0xFF;
	i2=col[2]&0xFF;
	i3=col[3]&0xFF;
	
	state[0][3] = gf_mul[i0][0];
	state[0][3] ^= gf_mul[i1][1];
	state[0][3] ^= col[2];
	state[0][3] ^= col[3];
	state[1][3] = col[0];
	state[1][3] ^= gf_mul[i1][0];
	state[1][3] ^= gf_mul[i2][1];
	state[1][3] ^= col[3];
	state[2][3] = col[0];
	state[2][3] ^= col[1];
	state[2][3] ^= gf_mul[i2][0];
	state[2][3] ^= gf_mul[i3][1];
	state[3][3] = gf_mul[i0][1];
	state[3][3] ^= col[1];
	state[3][3] ^= col[2];
	state[3][3] ^= gf_mul[i3][0];
	}

	//void InvMixColumns(BYTE state[][4])
	private static void InvMixColumns()
	{
	byte[] col=new byte[4];

	// Column 1
	col[0] = state[0][0];
	col[1] = state[1][0];
	col[2] = state[2][0];
	col[3] = state[3][0];
	
	int i0=col[0]&0xFF;
	int i1=col[1]&0xFF;
	int i2=col[2]&0xFF;
	int i3=col[3]&0xFF;
	
	state[0][0] = gf_mul[i0][5];
	state[0][0] ^= gf_mul[i1][3];
	state[0][0] ^= gf_mul[i2][4];
	state[0][0] ^= gf_mul[i3][2];
	state[1][0] = gf_mul[i0][2];
	state[1][0] ^= gf_mul[i1][5];
	state[1][0] ^= gf_mul[i2][3];
	state[1][0] ^= gf_mul[i3][4];
	state[2][0] = gf_mul[i0][4];
	state[2][0] ^= gf_mul[i1][2];
	state[2][0] ^= gf_mul[i2][5];
	state[2][0] ^= gf_mul[i3][3];
	state[3][0] = gf_mul[i0][3];
	state[3][0] ^= gf_mul[i1][4];
	state[3][0] ^= gf_mul[i2][2];
	state[3][0] ^= gf_mul[i3][5];
	// Column 2
	col[0] = state[0][1];
	col[1] = state[1][1];
	col[2] = state[2][1];
	col[3] = state[3][1];
	
	i0=col[0]&0xFF;
	i1=col[1]&0xFF;
	i2=col[2]&0xFF;
	i3=col[3]&0xFF;
	
	state[0][1] = gf_mul[i0][5];
	state[0][1] ^= gf_mul[i1][3];
	state[0][1] ^= gf_mul[i2][4];
	state[0][1] ^= gf_mul[i3][2];
	state[1][1] = gf_mul[i0][2];
	state[1][1] ^= gf_mul[i1][5];
	state[1][1] ^= gf_mul[i2][3];
	state[1][1] ^= gf_mul[i3][4];
	state[2][1] = gf_mul[i0][4];
	state[2][1] ^= gf_mul[i1][2];
	state[2][1] ^= gf_mul[i2][5];
	state[2][1] ^= gf_mul[i3][3];
	state[3][1] = gf_mul[i0][3];
	state[3][1] ^= gf_mul[i1][4];
	state[3][1] ^= gf_mul[i2][2];
	state[3][1] ^= gf_mul[i3][5];
	// Column 3
	col[0] = state[0][2];
	col[1] = state[1][2];
	col[2] = state[2][2];
	col[3] = state[3][2];
	
	i0=col[0]&0xFF;
	i1=col[1]&0xFF;
	i2=col[2]&0xFF;
	i3=col[3]&0xFF;
	
	state[0][2] = gf_mul[i0][5];
	state[0][2] ^= gf_mul[i1][3];
	state[0][2] ^= gf_mul[i2][4];
	state[0][2] ^= gf_mul[i3][2];
	state[1][2] = gf_mul[i0][2];
	state[1][2] ^= gf_mul[i1][5];
	state[1][2] ^= gf_mul[i2][3];
	state[1][2] ^= gf_mul[i3][4];
	state[2][2] = gf_mul[i0][4];
	state[2][2] ^= gf_mul[i1][2];
	state[2][2] ^= gf_mul[i2][5];
	state[2][2] ^= gf_mul[i3][3];
	state[3][2] = gf_mul[i0][3];
	state[3][2] ^= gf_mul[i1][4];
	state[3][2] ^= gf_mul[i2][2];
	state[3][2] ^= gf_mul[i3][5];
	// Column 4
	col[0] = state[0][3];
	col[1] = state[1][3];
	col[2] = state[2][3];
	col[3] = state[3][3];
	
	i0=col[0]&0xFF;
	i1=col[1]&0xFF;
	i2=col[2]&0xFF;
	i3=col[3]&0xFF;
	
	state[0][3] = gf_mul[i0][5];
	state[0][3] ^= gf_mul[i1][3];
	state[0][3] ^= gf_mul[i2][4];
	state[0][3] ^= gf_mul[i3][2];
	state[1][3] = gf_mul[i0][2];
	state[1][3] ^= gf_mul[i1][5];
	state[1][3] ^= gf_mul[i2][3];
	state[1][3] ^= gf_mul[i3][4];
	state[2][3] = gf_mul[i0][4];
	state[2][3] ^= gf_mul[i1][2];
	state[2][3] ^= gf_mul[i2][5];
	state[2][3] ^= gf_mul[i3][3];
	state[3][3] = gf_mul[i0][3];
	state[3][3] ^= gf_mul[i1][4];
	state[3][3] ^= gf_mul[i2][2];
	state[3][3] ^= gf_mul[i3][5];
	}

	/////////////////
	// (En/De)Crypt
	/////////////////

	//void aes_encrypt(const BYTE in[], BYTE out[], const WORD key[], int keysize)
	byte[] aes_encrypt(byte in[], int key[], int keysize)
	{
	//char[][] state=new char[4][4];
	byte[] out=new byte[16];
	
	// Copy input array (should be 16 bytes long) to a matrix (sequential bytes are ordered
	// by row, not col) called "state" for processing.
	// *** Implementation note: The official AES documentation references the state by
	// column, then row. Accessing an element in C requires row then column. Thus, all state
	// references in AES must have the column and row indexes reversed for C implementation.
	state[0][0] = in[0];
	state[1][0] = in[1];
	state[2][0] = in[2];
	state[3][0] = in[3];
	state[0][1] = in[4];
	state[1][1] = in[5];
	state[2][1] = in[6];
	state[3][1] = in[7];
	state[0][2] = in[8];
	state[1][2] = in[9];
	state[2][2] = in[10];
	state[3][2] = in[11];
	state[0][3] = in[12];
	state[1][3] = in[13];
	state[2][3] = in[14];
	state[3][3] = in[15];

	// Perform the necessary number of rounds. The round key is added first.
	// The last round does not perform the MixColumns step.
	AddRoundKey(key);
	
	/*SubBytes(state); ShiftRows(state); MixColumns(state); AddRoundKey(state,&key[4]);
	SubBytes(state); ShiftRows(state); MixColumns(state); AddRoundKey(state,&key[8]);
	SubBytes(state); ShiftRows(state); MixColumns(state); AddRoundKey(state,&key[12]);
	SubBytes(state); ShiftRows(state); MixColumns(state); AddRoundKey(state,&key[16]);
	SubBytes(state); ShiftRows(state); MixColumns(state); AddRoundKey(state,&key[20]);
	SubBytes(state); ShiftRows(state); MixColumns(state); AddRoundKey(state,&key[24]);
	SubBytes(state); ShiftRows(state); MixColumns(state); AddRoundKey(state,&key[28]);
	SubBytes(state); ShiftRows(state); MixColumns(state); AddRoundKey(state,&key[32]);
	SubBytes(state); ShiftRows(state); MixColumns(state); AddRoundKey(state,&key[36]);*/
	
		for (int i=1; i<=9; i++)
		{
		int[] aux_key=new int[4];
		aux_key[0]=key[i*4];
		aux_key[1]=key[i*4+1];
		aux_key[2]=key[i*4+2];
		aux_key[3]=key[i*4+3];
		SubBytes(); ShiftRows(); MixColumns(); AddRoundKey(aux_key);
		}
	
		if (keysize != 128) 
		{
		//SubBytes(state); ShiftRows(state); MixColumns(state); AddRoundKey(state,&key[40]);
		//SubBytes(state); ShiftRows(state); MixColumns(state); AddRoundKey(state,&key[44]);
			
			for (int i=10; i<=11; i++)
			{
			int[] aux_key=new int[4];
			aux_key[0]=key[i*4];
			aux_key[1]=key[i*4+1];
			aux_key[2]=key[i*4+2];
			aux_key[3]=key[i*4+3];
			SubBytes(); ShiftRows(); MixColumns(); AddRoundKey(aux_key);
			}
		
			if (keysize != 192) 
			{
			//SubBytes(state); ShiftRows(state); MixColumns(state); AddRoundKey(state,&key[48]);
			//SubBytes(state); ShiftRows(state); MixColumns(state); AddRoundKey(state,&key[52]);
			//SubBytes(state); ShiftRows(state); AddRoundKey(state,&key[56]);
				
				for (int i=12; i<=14; i++)
				{
				int[] aux_key=new int[4];
				aux_key[0]=key[i*4];
				aux_key[1]=key[i*4+1];
				aux_key[2]=key[i*4+2];
				aux_key[3]=key[i*4+3];
					
					if ( i!=14 ) 
					{
					SubBytes(); ShiftRows(); MixColumns(); AddRoundKey(aux_key);
					}
					else 
					{
					SubBytes(); ShiftRows(); AddRoundKey(aux_key);
					}
				}
				
			}
			else
			{
				for (int i=12; i<=12; i++)
				{
				int[] aux_key=new int[4];
				aux_key[0]=key[i*4];
				aux_key[1]=key[i*4+1];
				aux_key[2]=key[i*4+2];
				aux_key[3]=key[i*4+3];
				
				SubBytes(); ShiftRows(); AddRoundKey(aux_key);
				}
				
			
			}
		}
		else
		{
			for (int i=10; i<=10; i++)
			{
			int[] aux_key=new int[4];
			aux_key[0]=key[i*4];
			aux_key[1]=key[i*4+1];
			aux_key[2]=key[i*4+2];
			aux_key[3]=key[i*4+3];
			
			SubBytes(); ShiftRows(); AddRoundKey(aux_key);
			}
		
		}

	// Copy the state to the output array.
	out[0] = state[0][0];
	out[1] = state[1][0];
	out[2] = state[2][0];
	out[3] = state[3][0];
	out[4] = state[0][1];
	out[5] = state[1][1];
	out[6] = state[2][1];
	out[7] = state[3][1];
	out[8] = state[0][2];
	out[9] = state[1][2];
	out[10] = state[2][2];
	out[11] = state[3][2];
	out[12] = state[0][3];
	out[13] = state[1][3];
	out[14] = state[2][3];
	out[15] = state[3][3];
	return out;
	}

	
	
	//void aes_decrypt(const BYTE in[], BYTE out[], const WORD key[], int keysize)
	byte[] aes_decrypt(byte in[], int key[], int keysize)
	{
	byte[] out=new byte[16];

	// Copy the input to the state.
	state[0][0] = in[0];
	state[1][0] = in[1];
	state[2][0] = in[2];
	state[3][0] = in[3];
	state[0][1] = in[4];
	state[1][1] = in[5];
	state[2][1] = in[6];
	state[3][1] = in[7];
	state[0][2] = in[8];
	state[1][2] = in[9];
	state[2][2] = in[10];
	state[3][2] = in[11];
	state[0][3] = in[12];
	state[1][3] = in[13];
	state[2][3] = in[14];
	state[3][3] = in[15];

		// Perform the necessary number of rounds. The round key is added first.
		// The last round does not perform the MixColumns step.
		if (keysize > 128) 
		{
			if (keysize > 192) 
			{
				//AddRoundKey(state,&key[56]);
				//InvShiftRows(state);InvSubBytes(state);AddRoundKey(state,&key[52]);InvMixColumns(state);
				//InvShiftRows(state);InvSubBytes(state);AddRoundKey(state,&key[48]);InvMixColumns(state);
				for (int i=14; i>=12; i--)
				{
				int[] aux_key=new int[4];
				aux_key[0]=key[i*4];
				aux_key[1]=key[i*4+1];
				aux_key[2]=key[i*4+2];
				aux_key[3]=key[i*4+3];

					if ( i==14 ) AddRoundKey(aux_key);
					else
					{
					InvShiftRows();InvSubBytes();AddRoundKey(aux_key);InvMixColumns();
					}
				}

			}
			else 
			{
				//AddRoundKey(state,&key[48]);
				for (int i=12; i>=12; i--)
				{
				int[] aux_key=new int[4];
				aux_key[0]=key[i*4];
				aux_key[1]=key[i*4+1];
				aux_key[2]=key[i*4+2];
				aux_key[3]=key[i*4+3];
				AddRoundKey(aux_key);
				}
			}
		
		//InvShiftRows(state);InvSubBytes(state);AddRoundKey(state,&key[44]);InvMixColumns(state);
		//InvShiftRows(state);InvSubBytes(state);AddRoundKey(state,&key[40]);InvMixColumns(state);
			for (int i=11; i>=10; i--)
			{
			int[] aux_key=new int[4];
			aux_key[0]=key[i*4];
			aux_key[1]=key[i*4+1];
			aux_key[2]=key[i*4+2];
			aux_key[3]=key[i*4+3];
			InvShiftRows();InvSubBytes();AddRoundKey(aux_key);InvMixColumns();
			}
		
		}
		else 
		{
			//AddRoundKey(state,&key[40]);
			for (int i=10; i>=10; i--)
			{
			int[] aux_key=new int[4];
			aux_key[0]=key[i*4];
			aux_key[1]=key[i*4+1];
			aux_key[2]=key[i*4+2];
			aux_key[3]=key[i*4+3];
			AddRoundKey(aux_key);
			}
		}
	
		/*InvShiftRows(state);InvSubBytes(state);AddRoundKey(state,&key[36]);InvMixColumns(state);
		InvShiftRows(state);InvSubBytes(state);AddRoundKey(state,&key[32]);InvMixColumns(state);
		InvShiftRows(state);InvSubBytes(state);AddRoundKey(state,&key[28]);InvMixColumns(state);
		InvShiftRows(state);InvSubBytes(state);AddRoundKey(state,&key[24]);InvMixColumns(state);
		InvShiftRows(state);InvSubBytes(state);AddRoundKey(state,&key[20]);InvMixColumns(state);
		InvShiftRows(state);InvSubBytes(state);AddRoundKey(state,&key[16]);InvMixColumns(state);
		InvShiftRows(state);InvSubBytes(state);AddRoundKey(state,&key[12]);InvMixColumns(state);
		InvShiftRows(state);InvSubBytes(state);AddRoundKey(state,&key[8]);InvMixColumns(state);
		InvShiftRows(state);InvSubBytes(state);AddRoundKey(state,&key[4]);InvMixColumns(state);*/
		
		for (int i=9; i>=1; i--)
		{
		int[] aux_key=new int[4];
		aux_key[0]=key[i*4];
		aux_key[1]=key[i*4+1];
		aux_key[2]=key[i*4+2];
		aux_key[3]=key[i*4+3];
		InvShiftRows();InvSubBytes();AddRoundKey(aux_key);InvMixColumns();
		}
	
	InvShiftRows();InvSubBytes();AddRoundKey(key);
	// Copy the state to the output array.
	out[0] = state[0][0];
	out[1] = state[1][0];
	out[2] = state[2][0];
	out[3] = state[3][0];
	out[4] = state[0][1];
	out[5] = state[1][1];
	out[6] = state[2][1];
	out[7] = state[3][1];
	out[8] = state[0][2];
	out[9] = state[1][2];
	out[10] = state[2][2];
	out[11] = state[3][2];
	out[12] = state[0][3];
	out[13] = state[1][3];
	out[14] = state[2][3];
	out[15] = state[3][3];
	return out;
	}

	/*******************
	** AES DEBUGGING FUNCTIONS
	*******************/
	/*
	// This prints the "state" grid as a linear hex string.
	void print_state(BYTE state[][4])
	{
		int idx,idx2;
		for (idx=0; idx < 4; idx++)
			for (idx2=0; idx2 < 4; idx2++)
				printf("%02x",state[idx2][idx]);
		printf("\n");
	}
	// This prints the key (4 consecutive ints) used for a given round as a linear hex string.
	void print_rnd_key(WORD key[])
	{
		int idx;
		for (idx=0; idx < 4; idx++)
			printf("%08x",key[idx]);
		printf("\n");
	}
	*/

	
}
