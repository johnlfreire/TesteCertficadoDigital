package javaapplication2;


  
import java.io.FileInputStream;
import java.io.StringWriter;
import java.security.KeyStore;  
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
  
/** 
* Acessa dados dos Certificados Digitais por meio do repositorio do Windows (SunMSCAPI). 
*  
* @author Copyright (c) 2012 Maciel Gonçalves 
*  
* Este programa é software livre, você pode redistribuí-lo e ou modificá-lo 
* sob os termos da Licença Pública Geral GNU como publicada pela Free 
* Software Foundation, tanto a versão 2 da Licença, ou (a seu critério) 
* qualquer versão posterior. 
*  
* http://www.gnu.org/licenses/gpl.txt 
*  
*/  
public class DadosCertificadoRepositorioWindows {  
    private static final SimpleDateFormat dateFormat = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");  
         public static String assinaXML(String xml, String nome, KeyStore ks, char[] senha) throws Exception  
{     
  
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");  
  
        List<Transform> listTransforms = new ArrayList<>();  
        listTransforms.add(fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null));  
        listTransforms.add(fac.newTransform("http://www.w3.org/TR/2001/REC-xml-c14n-20010315", (TransformParameterSpec) null));  
  
        Reference ref = fac.newReference("",  
                fac.newDigestMethod(DigestMethod.SHA1, null),  
                listTransforms, null, null);  
        SignedInfo si = fac.newSignedInfo(fac.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE,  
                (C14NMethodParameterSpec) null),  
                fac.newSignatureMethod(SignatureMethod.RSA_SHA1, null),  
                Collections.singletonList(ref));  
  
        KeyStore.PrivateKeyEntry keyEntry  
                = (KeyStore.PrivateKeyEntry) ks.getEntry(nome, new KeyStore.PasswordProtection(senha));  
        X509Certificate cert = (X509Certificate) keyEntry.getCertificate();  
  
        KeyInfoFactory kif = fac.getKeyInfoFactory();  
        List x509Content = new ArrayList();  
        x509Content.add(cert);  
        X509Data xd = kif.newX509Data(x509Content);  
        KeyInfo ki = kif.newKeyInfo(Collections.singletonList(xd));  
          
         DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();  
            dbf.setNamespaceAware(true);  
            Document doc = dbf.newDocumentBuilder().parse(new FileInputStream("/teste.xml"));  
  
            // Create a DOMSignContext and specify the RSA PrivateKey and  
            // location of the resulting XMLSignature's parent element.  
            DOMSignContext dsc = new DOMSignContext(keyEntry.getPrivateKey(), doc.getDocumentElement());  
        XMLSignature signature = fac.newXMLSignature(si, ki);  
  
        signature.sign(dsc);  
  
        StringWriter writer = new StringWriter();  
        TransformerFactory tf = TransformerFactory.newInstance();  
        Transformer trans = tf.newTransformer();  
        trans.transform(new DOMSource(doc), new StreamResult(writer));  
  
        return writer.toString();  
}  
    public static void main(String[] args) {  
        try {  
            KeyStore keyStore = KeyStore.getInstance("Windows-MY", "SunMSCAPI");  
            keyStore.load(null, null);  
              
            Enumeration <String> al = keyStore.aliases();  
            while (al.hasMoreElements()) {  
                String alias = al.nextElement();  
                info("--------------------------------------------------------");  
                if (keyStore.containsAlias(alias)) {  
                    info("Emitido para........: " + alias);  
  
                    X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);  
                    info("SubjectDN...........: " + cert.getSubjectDN().toString());  
                    info("Version.............: " + cert.getVersion());  
                    info("SerialNumber........: " + cert.getSerialNumber());  
                    info("SigAlgName..........: " + cert.getSigAlgName());  
                    info("Válido a partir de..: " + dateFormat.format(cert.getNotBefore()));  
                    info("Válido até..........: " + dateFormat.format(cert.getNotAfter()));   
                   // assinaXML("",alias , keyStore, '1234');
                } else {  
                    info("Alias doesn't exists : " + alias);  
                }  
            }  
        } catch (Exception e) {  
            error(e.toString());  
        }  
       
    }  
  
    /** 
     * Info. 
     * @param log 
     */  
    private static void info(String log) {  
        System.out.println("INFO: " + log);  
    }  
  
    /** 
     * Error. 
     * @param log 
     */  
    private static void error(String log) {  
        System.out.println("ERROR: " + log);  
    }  
  
}  