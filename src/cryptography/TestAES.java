package cryptography;

import java.util.Random;

public class TestAES 
{
	public static void main(String[] args)
	{
	
	byte[] message={-119,  80,  78,  71,  13,  10,  26,  10,   0,   0,   0,  13,  73,  72,  68,  82};

		for (int i=0; i<16; i++) System.out.print((byte)message[i]+", ");
		System.out.println();
		System.out.println("*************");
	
	
	byte[] key=new byte[24];
	Random r=new Random();
	
		for (int i=0; i<24; i++) 
			key[i] = (byte)i;
	
	AES aes=new AES(key, 192);
	//Encrypt block of 16 bytes
	byte[] enc= new byte[192/8];
	aes.aes_encrypt(message, enc);
	
		for (int i=0; i<16; i++) System.out.print((byte)enc[i]+", ");
		System.out.println();
		System.out.println("*************");
		System.out.println("");
	
	
	//Decrypt block of 16 bytes
	byte[] dec= new byte[192/8];
	aes.aes_decrypt(enc, dec);
		
		for (int i=0; i<16; i++) System.out.print((byte)dec[i]+", ");
		System.out.println();
	
		
	}
	
}
