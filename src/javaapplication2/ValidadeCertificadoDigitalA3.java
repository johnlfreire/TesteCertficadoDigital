package javaapplication2;

  
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.StringWriter;
import java.security.KeyStore;  
import java.security.Provider;  
import java.security.ProviderException;  
import java.security.Security;  
import java.security.cert.Certificate;  
import java.security.cert.X509Certificate;  
import java.text.SimpleDateFormat;  
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;  
import java.util.List;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
  
public class ValidadeCertificadoDigitalA3 {  
    private static final SimpleDateFormat dateFormat = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");  
    
 
    public static void main(String[] args) {  
          
        try {  
            String senhaDoCertificadoDoCliente = "1234";  
              
            String fileCfg = "SmartCard.cfg";              
            Provider p = new sun.security.pkcs11.SunPKCS11(fileCfg);  
            //Security.addProvider(p);  
            char[] pin = senhaDoCertificadoDoCliente.toCharArray();  
            KeyStore keystore = KeyStore.getInstance("pkcs12");  
            keystore.load(null, pin);  
            
            Enumeration<String> eAliases = keystore.aliases();    
                
            while (eAliases.hasMoreElements()) {    
                
                String alias = (String) eAliases.nextElement();    
                Certificate certificado = (Certificate) keystore.getCertificate(alias);  
                
            
                info("Aliais: " + alias + " "  + certificado.getPublicKey());  
                X509Certificate cert = (X509Certificate) certificado;    
                
                info(cert.getSubjectDN().getName());  
                info("Válido a partir de..: " + dateFormat.format(cert.getNotBefore()));  
                info("Válido até..........: " + dateFormat.format(cert.getNotAfter()));    
                //assinaXML(fileCfg,alias , keystore, pin);
            }  
              
        } catch (ProviderException e) {  
            error(e.getMessage());  
        } catch (Exception e) {  
            error(e.toString());  
        }  
    }  
  
    /** 
     * Error. 
     * @param log 
     */  
    private static void error(String log) {  
        System.out.println("ERROR: " + log);  
    }  
  
    /** 
     * Info 
     * @param log 
     */  
    private static void info(String log) {  
        System.out.println("INFO: " + log);  
    }  
      
}  