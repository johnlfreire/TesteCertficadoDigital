package javaapplication2;

            
public class Test {
 public static void main(String[] args) {
  T x = new T("X", null);
  x.start();
  T y = new T("Y", x);
  y.start();
  T z = new T("Z", y);
  z.start();
 }
}
class T extends Thread {
 private Thread predecessor;
 private String name;
 public T(String name, Thread predecessor) {
  this.predecessor = predecessor;
  this.name = name;
 }
 public void run() {
  try {
   Thread.sleep((int)(Math.random() * 89));
   System.out.print(name);
  } catch (InterruptedException ie) {
   ie.printStackTrace();
  }
 }
}
