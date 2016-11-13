package cryptography;

//Example using DES class

public class TestDES 
{
	
	public static void main(String[] args)
	{
	DES des=new DES();
	
	//Generate a key
	char[] key=des.generate_key();
	
	//Generate key_set
	key_set[] key_sets=des.generate_sub_keys(key);
	
	char[] message={'h', 'o', 'l', 'a', 'e', 'r', 'w', 'n'};
	
		for (int i=0; i<8; i++) System.out.print(""+message[i]);
		System.out.println();
	
	//Encrypt block of 8 bytes
	char[] enc=des.process_message(message, key_sets, 1);
	
		for (int i=0; i<8; i++) System.out.print(""+enc[i]);
		System.out.println();
		
	//Decrypt block of 8 bytes
	char[] dec=des.process_message(enc, key_sets, 0);
		
		for (int i=0; i<8; i++) System.out.print(""+dec[i]);
		System.out.println();
	
	}
}
