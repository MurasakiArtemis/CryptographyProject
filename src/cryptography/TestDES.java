package cryptography;

import java.util.Random;

//Example using DES class

public class TestDES 
{
	
	public static void main(String[] args)
	{
	DES des=new DES();
	
	char[] message={'h', 'o', 'l', 'a', 'e', 'r', 'w', 'n'};
	
	for (int i=0; i<8; i++) System.out.print(""+message[i]);
	System.out.println();
	
	char[] key=new char[8];
	Random r=new Random();
	
		for (int i=0; i<7; i++) key[i] = (char)r.nextInt(255);
	
	
	//Encrypt block of 8 bytes
	char[] enc=des.process_message(message, key, 1);
	
		for (int i=0; i<8; i++) System.out.print(""+enc[i]);
		System.out.println();
		
	//Decrypt block of 8 bytes
	char[] dec=des.process_message(enc, key, 0);
		
		for (int i=0; i<8; i++) System.out.print(""+dec[i]);
		System.out.println();
	
	}
}
