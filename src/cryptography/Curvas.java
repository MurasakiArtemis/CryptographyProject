package cryptography;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.ArrayList;

public class Curvas {

	private ArrayList<Punto> puntos=new ArrayList<Punto>();
	private int resCuadraticos[];
	private int a;
	private int b;
	private long P;
	private int numPuntos;
	private int block_size=2;
	
	public Curvas()
	{
		this.a=20;
		this.b=12;
		this.P=71191;
		ResCua();
		CalPuntos();
	}
	
	public Curvas(int a,int b,long P) {
		this.a=a;
		this.b=b;
		this.P=P;
		ResCua();
		CalPuntos();
	}
	
	public Punto Suma(Punto p,Punto q){
		if(q==null)
			return p;
		long invY=P-(p.getY()%P);
		if((invY==q.getY())&&(p.getX()==q.getX()))
			return null;
		Punto r=new Punto();
		long aux1=0,aux2=0,phi=0;
		if((p.getX()==q.getX())){
			aux1=(3*(ExpMod(p.getX(), 2)))+a;
			aux2=2*p.getY();
		}
		else{
			aux1=p.getY()-q.getY();
			aux2=p.getX()-q.getX();
		}
		if(aux1<0)
			aux1=P-((aux1*-1)%P);
		else
			aux1=aux1%P;
		if(aux2<0)
			aux2=P-((aux2*-1)%P);
		else
			aux2=aux2%P;
		if((aux1%aux2)!=0)
			phi=(aux1*EucExt(aux2))%P;
		else
			phi=(aux1/aux2)%P;
		r.setX(((phi*phi)-p.getX()-q.getX())%P);
		r.setY(((phi*(p.getX()-r.getX()))-p.getY())%P);
		if(r.getX()<0)
			r.setX(P-((r.getX()*-1)%P));
		if(r.getY()<0)
			r.setY(P-((r.getY()*-1)%P));
		return r;
	}
	
	private long ExpMod(long base,int exponente){
		long res=1;
		String aux=Integer.toBinaryString(exponente);
		for(int i=0;i<aux.length();i++){
			res=((res*res)%P);
			if(aux.charAt(i)=='1'){
				res=(res*base)%P;
			}
		}
		return res;
	}
	
	private long EucExt(long a){
		long x1=1,y1=0,x2=0,y2=1,u=0,v=0,q=0,r=0,x=0,y=0;
		u=a;
		v=P;

		while(u!=0){
			q=v/u;
			r=v-(q*u);
			x=x2-(q*x1);
			y=y2-(q*y1);
			v=u;
			u=r;
			x2=x1;
			x1=x;
			y2=y1;
			y1=y;
		}
		x=x2;
		y=y2;

		if(x<0)
			x=P-((x*(-1))%P);
		else
			x=x%P;

		return x;
	}
	
	private void ResCua(){
		int q[]=new int[(int)P/2];
		for(int i=1;i<=(P/2);i++){
			q[i-1]=(int)((i*i)%P);
			System.out.println(q[i-1]);
		}
		resCuadraticos=q;
		return;
	}
	
	private void CalPuntos(){
		ArrayList<Punto> puntos=new ArrayList<Punto>();
		long aux=0;
		for(int i=0;i<P;i++){
			aux=(ExpMod(i, 3)+(i*a)+b)%P;
			System.out.println("i= "+i+" aux= "+aux);
			for(int j=0;j<resCuadraticos.length;j++){
				if(aux==resCuadraticos[j]){
					puntos.add(new Punto(i,j+1));
					System.out.println("	x= "+i+" y= "+(j+1));
					puntos.add(new Punto(i,P-(j+1)));
					System.out.println("	x= "+i+" y= "+(P-(j+1)));
				}
			}
		}
		this.puntos=puntos;
		numPuntos=puntos.size()+1;
		return;
	}
	
	public Punto dobladoPunto(Punto p,long k){
		Punto xy=p;
		for(int i=0;i<k-1;i++){
			if(xy==null)
				System.out.println("Punto al infinito");
			xy=Suma(p, xy);
		}
		System.out.println(k+"P("+xy.getX()+","+xy.getY()+")");
		return xy;
	}
	
	public CurvesKey[] generateKeyPair()
	{
		CurvesKey[] keys = new CurvesKey[2];
		keys[0] = new CurvesKey(generarLlavePrivada());
		keys[1] = generarLlavePublica(keys[0].m);
		return keys;
	}
	
	public CurvesKey generarLlavePublica(int m){
		SecureRandom random=new SecureRandom();
		Punto p=puntos.get(random.nextInt(numPuntos-1));
		return new CurvesKey(p, dobladoPunto(p, m));
	}
	
	public int generarLlavePrivada(){
		SecureRandom random=new SecureRandom();
		return random.nextInt((int)P-1);
	}
	
	private Punto pointCompress(Punto p){
		return new Punto(p.getX(),p.getY()%2);
	}
	
	private Punto pointDescompress(Punto p){
		long z=(ExpMod(p.getX(), 3)+(a*p.getX())+b)%P;
		boolean con=true;
		for(int i=0;i<resCuadraticos.length;i++){
			if(z==resCuadraticos[i]){
				con=false;
				break;
			}
		}
		if(con)
			return null;
		long y=ExpMod(z, (int)(P+1)/4);
		if((y%2)==p.getY())
			return new Punto(p.getX(),y);
		else
			return new Punto(p.getX(),P-y);
	}

	public /*File*/ void cifrado(File file, File outfile, CurvesKey llave){
		//File outfile=new File(file.getParent()+"\\llavec.txt");
		Punto kp=null;
		int x=0;
		long x0=0;
		Punto x0y0=null;
		Punto p=llave.generator;
		Punto q=llave.q;
		try{
			FileInputStream fIn = new FileInputStream(file);
			FileOutputStream fOut = new FileOutputStream(outfile);
			byte[] key = new byte[block_size];
			//int tam=(int) file.length();
			SecureRandom random=new SecureRandom();
			long k=(random.nextInt((int)P-1))+1;
			long aux=0;
			PuntoCC res=new PuntoCC();
			kp=dobladoPunto(p, k);
			x0y0=dobladoPunto(q, k);
			fOut.write((int)file.length());
			do{
				fIn.read(key);
				x=ByteBuffer.wrap(key).getShort()&(0x0000ffff);
				System.out.println("Binario x= "+Integer.toBinaryString(x));
				System.out.println("Decimal x= "+x);
				aux=(x*x0y0.getX())&(0x00000000ffffffff);
				res.setX(pointCompress(kp));
				res.setY(aux%P);		
				fOut.write(ByteBuffer.allocate(2).putShort((short)res.getX().getX()).array());
				fOut.write(ByteBuffer.allocate(2).putShort((short)res.getX().getY()).array());
				fOut.write(ByteBuffer.allocate(2).putShort((short)res.getY()).array());
			}while(fIn.available()!=0);
			fIn.close();
			fOut.close();
		}catch(Exception e){
			e.printStackTrace();
		}
		//return outfile;
	}
	
	public PuntoCC cifrado(int x, CurvesKey key){
		Punto p = key.generator;
		Punto q = key.q;
		Punto kp=null;
		Punto x0y0=null;
		long aux=0;
		try{
			SecureRandom random=new SecureRandom();
			long k=(random.nextInt((int)P-1))+1;
			kp=dobladoPunto(p, k);
			x0y0=dobladoPunto(q, k);
			aux=(x*x0y0.getX())&(0x00000000ffffffff);
		}catch(Exception e){
			e.printStackTrace();
		}
		return new PuntoCC(pointCompress(kp),aux%P);
	}
	
	public /*File*/ void descifrado(File file, File outfile, CurvesKey ckey){
		int m = ckey.m;
		//File outfile=new File(file.getParent()+"\\llaved.txt");
		PuntoCC c=new PuntoCC();
		Punto aux=new Punto();
		Punto p=new Punto();
		long res=0;
		try {
			FileInputStream fIn = new FileInputStream(file);
			FileOutputStream fOut = new FileOutputStream(outfile);
			byte[] key = new byte[block_size];
			int tam=fIn.read();
			for(int i=0;i<((tam/2)+(tam%2));i++){
				fIn.read(key);
				aux.setX(ByteBuffer.wrap(key).getShort()&(0x0000ffff));
				fIn.read(key);
				aux.setY(ByteBuffer.wrap(key).getShort()&(0x0000ffff));
				c.setX(aux);
				fIn.read(key);
				c.setY(ByteBuffer.wrap(key).getShort()&(0x0000ffff));
				p=pointDescompress(c.getX());
				p=dobladoPunto(p, m);
				res=(EucExt(p.getX())*c.getY())%P;
				fOut.write(ByteBuffer.allocate(2).putShort((short)res).array());
			}
			fIn.close();
			fOut.close();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		//return outfile;
	}
	
	public long descifrado(PuntoCC c, CurvesKey key){
		int m = key.m;
		Punto p=pointDescompress(c.getX());
		p=dobladoPunto(p, m);
		return (EucExt(p.getX())*c.getY())%P;
	}
	
	public boolean validarCurva(){
		if(P%4!=3)
			return false;
		if((((4*ExpMod(a, 3))+(27*ExpMod(b, 2)))%P)==0)
			return false;
		return true;
	}
}
