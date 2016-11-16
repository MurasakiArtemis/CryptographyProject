package cryptography;

import java.io.File;
import java.security.SecureRandom;

public class TestWn {

	public static void main(String[] args) throws Exception 
	{
		CipherDecipher cipher_decipher = new CipherDecipher(Algorithm.AES128);
		File origin_file = new File("Pixiv.png");
		File destination_file = new File("Pixiv_AES128_Cipher.png");
		File recovered_file = new File("Pixiv_AES128_Decipher.png");
		cipher_decipher.encipher(origin_file, destination_file, OperationModes.ECB);
		cipher_decipher.decipher(destination_file, recovered_file);
		/*byte[] key = new byte[]{1, 1, 2, 3, 4, 5, 6, 7};
		//SecureRandom rand = new SecureRandom();
		//rand.nextBytes(key);
		//key[7] = 0;
		DES des = new DES(key);
		byte[] origin = new byte[]{'B', 'B', 'C', 'D', 'E', 'F', 'G', 'H'};
		byte[] result = new byte[8];
		des.process_message(origin, result, 0);*/
	}

}
