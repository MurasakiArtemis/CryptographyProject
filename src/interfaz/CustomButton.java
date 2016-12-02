package interfaz;

import javax.swing.JButton;

public class CustomButton extends JButton 
{
	public String owner;
	
	public CustomButton(String name, String owner)
	{
		super(name);
		this.owner = owner;
	}
}
