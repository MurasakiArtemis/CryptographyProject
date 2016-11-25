package cryptography;

import java.util.ArrayList;

public class Curvas {

	private ArrayList<Punto> puntos=new ArrayList<Punto>();
	private int a;
	private int b;
	
	public Curvas(int a,int b) {
		this.a=a;
		this.b=b;
	}
	
	public Punto Suma(Punto p,Punto q,int P){
		if(q==null)
			return p;
		int negY=p.getY()*(-1);
		int invY=P-((negY*-1)%P);
		if(invY==q.getY())
			return null;
		Punto r=new Punto();
		int aux1=0,aux2=0,phi=0;
		if((p.getX()==q.getX())){
			aux1=(3*((int)Math.pow(p.getX(), 2)))+a;
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
			phi=(aux1*EucExt(aux2, P))%P;
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
	
	private int ExpMod(int base,int exponente,int n){
		int res=1;
		String aux=Integer.toBinaryString(exponente);
		for(int i=0;i<aux.length();i++){
			res=((res*res)%n);
			if(aux.charAt(i)=='1'){
				res=(res*base)%n;
			}
		}
		System.out.println(res);
		return res;
	}
	
	private int EucExt(int a,int n){
		int x1=1,y1=0,x2=0,y2=1,u=0,v=0,q=0,r=0,x=0,y=0;
		u=a;
		v=n;

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
			x=n-((x*(-1))%n);
		else
			x=x%n;

		return x;
	}
	
	private int[] ResCua(int n){
		int q[]=new int[n/2];
		for(int i=1;i<=(n/2);i++){
			q[i-1]=(i*i)%n;
			System.out.println(q[i-1]);
		}
		return q;
	}
	
	public ArrayList<Punto> CalPuntos(int n){
		ArrayList<Punto> puntos=new ArrayList<Punto>();
		int aux=0;
		int rescua[]=ResCua(n);
		for(int i=0;i<n;i++){
			aux=(int)(Math.pow(i, 3)+(i*a)+b)%n;
			System.out.println("i= "+i+" aux= "+aux);
			for(int j=0;j<rescua.length;j++){
				if(aux==rescua[j]){
					puntos.add(new Punto(i,j+1));
					System.out.println("	x= "+i+" y= "+(j+1));
					puntos.add(new Punto(i,n-(j+1)));
					System.out.println("	x= "+i+" y= "+(n-(j+1)));
				}
			}
			System.out.println(puntos.size());
		}
		return puntos;
	}

	public static void main(String[] args) {
		Curvas c=new Curvas(2,7);
		Punto p=new Punto(28,6);
		Punto q=new Punto(28,6);
		for(int i=0;i<23;i++){
			if(q==null)
				System.out.println("Punto al infinito");
			else
				System.out.println((i+1)+"P("+q.getX()+","+q.getY()+")");
			q=c.Suma(p, q, 31);
		}
		/*System.out.println(c.EucExt(2, 31));
		Punto r=c.Suma(new Punto(2,9), new Punto(0,10), 31);
		System.out.println(r.getX());
		System.out.println(r.getY());
		/*System.out.println(c.EucExt(6, 17));*/
	}
}
