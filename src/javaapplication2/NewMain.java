/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package javaapplication2;

/**
 *
 * @author johnpc
 */
public class NewMain {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        String [] estados = {"SP","PR","SC","RS","MS","RO","AC","AM","RR","PA","AP","TO","MA","RN","PB","PE","AL","SE","BA","MG","RJ","MT","GO","DF","PI","CE","ES"}; 
       int cont=0;
        while(cont < estados.length) {
            System.out.println(estados[cont]);
            cont++;
    }
    }
}
