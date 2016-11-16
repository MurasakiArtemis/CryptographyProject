package cryptography;

//Example using DES class

public class TestDES 
{
	
	public static void main(String[] args)
	{
	
	//Generate a key
	byte[] key= new byte[8];
	DES des=new DES(key);
	//Generate key_set

	byte[] message={'h', 'o', 'l', 'a', 'e', 'r', 'w', 'n'};
	
		for (int i=0; i<8; i++) System.out.print(""+(char)message[i]);
		System.out.println();
	
	//Encrypt block of 8 bytes
	byte[] enc= new byte[8];
	des.process_message(message, enc, 1);
	
		for (int i=0; i<8; i++) System.out.print(""+enc[i]);
		System.out.println();
		
	//Decrypt block of 8 bytes
	byte[] dec= new byte[8];
	des.process_message(enc, dec, 0);
		
		for (int i=0; i<8; i++) System.out.print(""+(char)dec[i]);
		System.out.println();
	System.out.print("F");
	
	}
}
