package cryptography;

import java.util.Random;

public class TestAES 
{
	public static void main(String[] args)
	{
	AES aes=new AES();
	
	byte[] message={'h', 'o', 'l', 'a', 'e', 'r', 'w', 'n', 'h', 'o', 'l', 'a', 'e', 'r', 'w', 'N'};
	
		for (int i=0; i<16; i++) System.out.print(""+(char)message[i]);
		System.out.println();
		System.out.println("*************");
	
	byte[] key=new byte[24];
	Random r=new Random();
	
		for (int i=0; i<24; i++) key[i] = (byte)r.nextInt(255);
	
	
	//aes_key_setup needed to do enc/dec, we can move this to the constructor... we only need to pass the key like DES
	int[] setup=aes.aes_key_setup(key, 192);
	
	//Encrypt block of 16 bytes
	byte[] enc=aes.aes_encrypt(message, setup, 192);
	
		for (int i=0; i<16; i++) System.out.print(""+(char)enc[i]);
		System.out.println();
		System.out.println("*************");
		System.out.println("");
	
	
	//Decrypt block of 16 bytes
	byte[] dec=aes.aes_decrypt(enc, setup, 192);
		
		for (int i=0; i<16; i++) System.out.print(""+(char)dec[i]);
		System.out.println();
	
		
	}
	
}
