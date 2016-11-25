package interfaz;

import java.awt.Color;
import java.awt.Rectangle;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.io.File;
import java.util.StringTokenizer;

import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.JToolBar;
import javax.swing.border.TitledBorder;

import cryptography.Algorithm;
import cryptography.CipherDecipher;
import cryptography.OperationModes;
import net.iharder.dnd.FileDrop;

public class Interfaz {
	
	JFrame f=new JFrame("Proyecto");
	JDialog dllavero;
	String origen,destino,rutaLlavero;
	File[] archivos;
	int numArchivos;
	OperationModes modo_seleccionado=OperationModes.CBC;
	Algorithm cifrado=Algorithm.AES192;
	JTextArea consola=new JTextArea();
	JTextArea lblfiles;

	public Interfaz() {
		
		JPanel  myPanel = new JPanel();
		JFileChooser jfc=new JFileChooser();
		JButton rutab=new JButton("Ruta destino");
		JButton bllavero=new JButton("Ruta Llavero");
		JFileChooser fcllavero=new JFileChooser();
		JButton bcifrar=new JButton("Cifrar");
		JButton bdescifrar=new JButton("Descifrar");
		JLabel l1,l2,l3;
		JToolBar barra=new JToolBar("Herramimentas");
		String[] smodo={"CBC","CTR"};
		String[] scif={"AES128","AES192","AES256","3DES"};
		JComboBox modo=new JComboBox(smodo);
		JComboBox cif=new JComboBox(scif);
		JTextField rutat=new JTextField();
				
		barra.setBounds(new Rectangle(0,0,500,25));
		barra.setFloatable(false);
		myPanel.setBounds(new Rectangle(10,35,250,150));
		myPanel.setBackground(Color.WHITE);
		myPanel.setBorder(new TitledBorder("Arrastra aqui tus archvos"));
		l1=new JLabel("Ruta para archivos cifrados:");
		l1.setBounds(new Rectangle(10,200,250,20));
		l2=new JLabel("Modo de operación:");
		l2.setBounds(new Rectangle(10,270,150,25));
		jfc.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
		fcllavero.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
		rutab.setBounds(new Rectangle(350,230,120,25));
		bcifrar.setBounds(new Rectangle(260,300,100,25));
		bdescifrar.setBounds(new Rectangle(380,300,100,25));
		modo.setBounds(new Rectangle(10,300,100,25));
		cif.setBounds(new Rectangle(130,300,100,25));
		rutat.setBounds(new Rectangle(10,230,330,25));
		consola.setEditable(false);
		consola.setBorder(new TitledBorder("Consola"));
		JScrollPane scrollc=new JScrollPane(consola);
		scrollc.setBounds(new Rectangle(0,350,495,125));
		
		/************	Accion para el combo box del modo de operacion	**************/
		
		modo.addItemListener(new ItemListener() {
			
			@Override
			public void itemStateChanged(ItemEvent e) {
				// TODO Auto-generated method stub
				if(((String)modo.getSelectedItem()).equals("CBC"))
					modo_seleccionado=OperationModes.CBC;
				else
					modo_seleccionado=OperationModes.CTR;
			}
		});
		
		/************	Accion para el combo box del modo de operacion	**************/
		
		cif.addItemListener(new ItemListener() {
			
			@Override
			public void itemStateChanged(ItemEvent e) {
				// TODO Auto-generated method stub
				if(((String)cif.getSelectedItem()).equals("AES128"))
					cifrado=Algorithm.AES128;
				else if(((String)cif.getSelectedItem()).equals("AES192"))
					cifrado=Algorithm.AES192;
				else if(((String)cif.getSelectedItem()).equals("AES256"))
					cifrado=Algorithm.AES256;
				else if(((String)cif.getSelectedItem()).equals("3DES"))
					cifrado=Algorithm.DES168;
			}
		});
		
		/************	Accion al soltar archivos en "myPanel"	**************/
		lblfiles = new JTextArea();
		myPanel.add(lblfiles);
		new  FileDrop( myPanel, new FileDrop.Listener(){
			public void  filesDropped( java.io.File[] files ){
				numArchivos=files.length;
				lblfiles.setText("");
				archivos=files;
				for(int i=0;i<numArchivos;i++){
					lblfiles.setText(lblfiles.getText() + archivos[i].getName() + "\n");
				}
			}
		});
		
		/************	Accion del boton para la ruta de destino	**************/
		
		rutab.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent arg0) {
				jfc.showSaveDialog(null);
				if(jfc.getSelectedFile()==null){
					JOptionPane.showMessageDialog(null, "No seleccionaste ninguna ruta", "Error", JOptionPane.ERROR_MESSAGE);
				}
				else{
					destino=jfc.getSelectedFile().getAbsolutePath();
					rutat.setText(destino);
				}
			}
		});
		
		/************	Accion del boton para la ruta del llavero	**************/
		
		bllavero.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent arg0) {
				fcllavero.showSaveDialog(null);
				if(jfc.getSelectedFile()==null){
					JOptionPane.showMessageDialog(null, "No seleccionaste ninguna ruta", "Error", JOptionPane.ERROR_MESSAGE);
				}
				else{
					rutaLlavero=fcllavero.getSelectedFile().getAbsolutePath();
				}
			}
		});
		
		/************	Accion del boton para cifrar	**************/
		
		bcifrar.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent arg0) {
				if(archivos==null){
					JOptionPane.showMessageDialog(null, "No hay archivos para cifrar", "Error", JOptionPane.ERROR_MESSAGE);
				}
				else{
					if(destino==null){
						JOptionPane.showMessageDialog(null, "No hay ruta de destino", "Error", JOptionPane.ERROR_MESSAGE);
					}
					else{
						for(int i=0;i<numArchivos;i++){
							cifrar(archivos[i]);
						}
					}
				}
			}
		});
		
		/************	Accion del boton para descifrar	**************/
		
		bdescifrar.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent arg0) {
				if(archivos==null){
					JOptionPane.showMessageDialog(null, "No hay archivos para descifrar", "Error", JOptionPane.ERROR_MESSAGE);
				}
				else{
					if(destino==null){
						JOptionPane.showMessageDialog(null, "No hay ruta de destino", "Error", JOptionPane.ERROR_MESSAGE);
					}
					else{
						if(new File(destino+"\\llave.txt").exists()){
							for(int i=0;i<numArchivos;i++){
								descifrar(archivos[i]);
							}
						}
						else{
							JOptionPane.showMessageDialog(null, "No existe el archivo para la llave", "Error", JOptionPane.ERROR_MESSAGE);
						}
					}
				}
			}
		});
		
		barra.add(bllavero);
		f.setLayout(null);
		f.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		f.setSize(500, 500);
	    f.setLocationRelativeTo(null);
	    f.setResizable(false);
	    f.setVisible(true);
	    f.getContentPane().add(barra);
	    f.add(myPanel);
	    f.add(rutab);
	    f.add(l1);
	    f.add(l2);
	    f.add(bcifrar);
	    f.add(bdescifrar);
	    f.add(modo);
	    f.add(cif);
	    f.add(rutat);
	    f.add(scrollc);
	}

	public void cifrar(File archivo_origen){
		StringTokenizer tok=new StringTokenizer(archivo_origen.getName(), ".");
		File archivo_destino=new File(destino+"\\"+tok.nextToken()+"_Cipher."+tok.nextToken());
		File llave=new File(destino+"\\llave.txt");
	    try {
	    	CipherDecipher cipher_decipher=new CipherDecipher(llave,cifrado);
			cipher_decipher.encipher(archivo_origen, archivo_destino, modo_seleccionado);
			consola.setSelectedTextColor(Color.BLUE);
			consola.append("Se a creado el archivo llave "+llave.getName()+" en el directorio a actual\n");
			consola.append("Archivo "+archivo_destino.getName()+" cifrado con exito\n");
		} catch (Exception e) {
			// TODO Auto-generated catch block
			consola.setSelectedTextColor(Color.RED);
			consola.append("Se a creado el archivo llave "+llave.getName()+" en el directorio a actual\n");
		}
	}
	
	public void descifrar(File archivo_origen){
		StringTokenizer tok=new StringTokenizer(archivo_origen.getName(), ".");
		File archivo_destino=new File(destino+"\\"+tok.nextToken()+"_Decipher."+tok.nextToken());
		File llave=new File(destino+"\\llave.txt");
	    try {
	    	CipherDecipher cipher_decipher=new CipherDecipher(llave);
			cipher_decipher.decipher(archivo_origen, archivo_destino);
			consola.append("Archivo "+archivo_destino.getName()+" descifrado con exito\n");
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}	
	}

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		Interfaz i=new Interfaz();
	}

}
