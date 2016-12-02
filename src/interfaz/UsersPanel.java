package interfaz;

import java.awt.Color;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.io.IOException;

import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;

import cryptography.KeyRing;

class UserDescription extends JPanel
{
	private static final long serialVersionUID = 1L;
	KeyRing key_ring;
	UsersPanel parent;
	
	UserDescription(UsersPanel parent, KeyRing key_ring, String name, int i)
	{
		this.parent = parent;
		this.key_ring = key_ring;
		if(i % 2 == 0)
			this.setBackground(Color.WHITE);
		this.setLayout(new GridBagLayout());
		GridBagConstraints c = new GridBagConstraints();
		c.fill = GridBagConstraints.HORIZONTAL;
		//Nombre dueño
		JLabel label = new JLabel(name);
		c.weightx = 0.6;
		c.gridwidth = 3;
		c.gridx = 0;
		this.add(label, c);
		//Botón eliminar
		CustomButton button = new CustomButton("Eliminar", name);
		button.addActionListener(e -> {
			parent.remove(this);
			CustomButton caller = (CustomButton)e.getSource();
			try {
				String owner = caller.owner;
				key_ring.delete_public_key(caller.owner);
			} catch (IOException e1) {
				System.out.println(e1.getMessage());
			}
			parent.revalidate();
			parent.repaint();
		});
		c.gridwidth = 1;
		c.weightx = 0.2;
		c.gridx = 3;
		this.add(button, c);
		//Botón exportar
		button = new CustomButton("Exportar", name);
		button.addActionListener(e -> {
			CustomButton caller = (CustomButton)e.getSource();
			JFileChooser fcllavero = new JFileChooser();
			fcllavero.showSaveDialog(null);
			if(fcllavero.getSelectedFile()==null)
				JOptionPane.showMessageDialog(null, "No seleccionaste ninguna ruta", "Error", JOptionPane.ERROR_MESSAGE);
			else
				key_ring.export_public_key(caller.owner, fcllavero.getSelectedFile());
		});
		c.gridx = 4;
		this.add(button, c);
	}
}

public class UsersPanel extends JPanel 
{
	private static final long serialVersionUID = 1L;
	KeyRing key_ring;
	JScrollPane panel; 
	public UsersPanel(KeyRing key_ring)
	{
		this.key_ring = key_ring;
		this.setLayout(new BoxLayout(this, BoxLayout.PAGE_AXIS));
		add_components();
	}

	private void add_components()
	{
		if(key_ring == null)
			return;
		int i = 0;
		JPanel jp = new JPanel();
		jp.setLayout(new BoxLayout(jp, BoxLayout.PAGE_AXIS));
		for(String name : this.key_ring.key_ring.keySet())
		{
			if(name.contains("self"))
				continue;
			UserDescription ud = new UserDescription(this, key_ring, name, i++);
			jp.add(ud);
		}
		this.panel = new JScrollPane(jp);
		panel.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        panel.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        this.add(panel);
	}
	
	public void repaint()
	{
		this.removeAll();
		add_components();
		super.repaint();
	}
}
