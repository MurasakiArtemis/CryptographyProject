package interfaz;

import java.awt.Color;
import java.awt.Container;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.io.File;
import java.io.IOException;
import java.util.Random;

import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.border.TitledBorder;

import cryptography.KeyRing;
import net.iharder.dnd.FileDrop;
import net.iharder.dnd.FileDrop.Listener;

public class KeyRingManager 
{
	private JFrame frame = new JFrame("Llavero");
	private Container window = frame.getContentPane();
	private KeyRing key_ring;
	private UsersPanel key_ring_panel;
	
	public KeyRingManager(KeyRing key_ring)
	{
		this.key_ring = key_ring;
		
		window.setLayout(new GridBagLayout());
		GridBagConstraints c = new GridBagConstraints();
		//Panel de llaves contenidas
		key_ring_panel = new UsersPanel(key_ring);
		key_ring_panel.setBorder(new TitledBorder("Llaves registradas"));
		key_ring_panel.setBackground(Color.WHITE);
		c.fill = GridBagConstraints.BOTH;
		c.weightx = 0.5;
	    c.weighty = 0.7;
		c.gridwidth = 3;
		c.gridheight = 3;
		c.gridx = 0;
		c.gridy = 3;
		window.add(key_ring_panel, c);
		//Panel para arrastrar las llaves
		c.weightx = 0.5;
	    c.weighty = 0.3;
		JPanel drop_panel = new JPanel();
		drop_panel.setBackground(Color.WHITE);
		drop_panel.setBorder(new TitledBorder("Arrastra aqui las llaves"));
		new FileDrop(drop_panel, new Listener()
		{
			public void filesDropped(File[] files)
			{
				for(File file : files)
				{
					key_ring.import_public_key(file.getName(), file);
				}
				key_ring_panel.revalidate();
				key_ring_panel.repaint();
				JOptionPane.showMessageDialog(null, "Llaves agregadas correctamente");
			}
		});
		c.gridwidth = 2;
		c.gridheight = 2;
		c.gridx = 0;
		c.gridy = 0;
		window.add(drop_panel, c);
		c.weightx = 0.0;
		c.weighty = 0.15;
		//Botón Exportar
		JButton button = new JButton("Exportar llave pública personal");
		button.addActionListener(e -> {
			JFileChooser fcllavero = new JFileChooser();
			fcllavero.showSaveDialog(null);
			if(fcllavero.getSelectedFile()==null)
				JOptionPane.showMessageDialog(null, "No seleccionaste ninguna ruta", "Error", JOptionPane.ERROR_MESSAGE);
			else
				key_ring.export_public_key("self_public", fcllavero.getSelectedFile());
		});
		c.fill = GridBagConstraints.HORIZONTAL;
		c.gridwidth = 1;
		c.gridheight = 1;
		c.gridx = 2;
		c.gridy = 0;
		window.add(button, c);
		//Botón generar llaves
		button = new JButton("Generar llaves");
		button.addActionListener(e -> {
			byte[] public_key = new byte[10];
			byte[] private_key = new byte[10];
			try {
				key_ring.add_key_pair(public_key, private_key);
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
		});
		c.gridwidth = 1;
		c.gridheight = 1;
		c.gridx = 2;
		c.gridy = 1;
		window.add(button, c);
		frame.pack();
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.setSize(500, 500);
		frame.setVisible(true);
	}
	
	public static void main(String[] args) throws IOException 
	{
		KeyRing key_ring = new KeyRing(new File("C:\\Users\\erwin\\Desktop\\keyring.key"));
		Random rand = new Random();
		key_ring.add_key_pair(new String("MyKey").getBytes(), new String("MyKey").getBytes());
		String key1 = "ABCDE";
		byte[] add = new byte[5];
		for(int i = 0; i < 5; i++)
		{
			rand.nextBytes(add);
			key_ring.add_public_key(key1 + new String(add), key1.getBytes());
		}
		KeyRingManager ui = new KeyRingManager(key_ring);
	}

}
