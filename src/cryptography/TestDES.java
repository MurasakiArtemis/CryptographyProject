package cryptography;

public class TestDES 
{
	public static void main(String[] args)
	{
	DES des=new DES();
	char[] key=des.generate_key();
	key_set[] key_sets=des.generate_sub_keys(key);
	
	char[] message={'h', 'o', 'l', 'a', 'e', 'r', 'w', 'n'};
	
		for (int i=0; i<8; i++) System.out.print(""+message[i]);
		System.out.println();
	
	char[] enc=des.process_message(message, key_sets, 1);
	
		for (int i=0; i<8; i++) System.out.print(""+enc[i]);
		System.out.println();
		
	char[] dec=des.process_message(enc, key_sets, 0);
		
		for (int i=0; i<8; i++) System.out.print(""+dec[i]);
		System.out.println();
	
	
	}
}
