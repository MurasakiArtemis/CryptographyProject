package cryptography;

import java.io.File;
/*import java.security.SecureRandom;
import java.util.Random;*/

public class TestWn {

	public static void main(String[] args) throws Exception 
	{
		CipherDecipher cipher_decipher = new CipherDecipher(Algorithm.AES192);
		/*byte[] key = new byte[21];
		for(int i = 0; i < 21; i++)
			key[i] = (byte)i;
		CipherDecipher cipher_decipher = new CipherDecipher(key);*/
		/*File origin_file = new File("Test.txt");
		File destination_file = new File("Test_AES192_Cipher.txt");
		File recovered_file = new File("Test_AES192_Decipher.txt");*/
		File origin_file = new File("Pixiv.png");
		File destination_file = new File("Pixiv_AES192_Cipher.png");
		File recovered_file = new File("Pixiv_AES192_Decipher.png");
		cipher_decipher.encipher(origin_file, destination_file, OperationModes.ECB);
		cipher_decipher.decipher(destination_file, recovered_file);
	}

}
