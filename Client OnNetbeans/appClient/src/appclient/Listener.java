package appclient;

import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSession;
import javax.security.auth.x500.X500Principal;


/**
 * 
 * Listener
 * Date: Janvier 8-2017
 * @author Mouad Bounabi
 *@version 1.0
 *
 */
public class Listener implements Runnable{

    
    
  
    private OutputStream outputStream;
    /**
    * String Url de la requete
    */
    private String url;
    /**
     * String Chemin courant où les fichier seront Telecharger/uploader
     */
    private String pathFile;
    /**
     * String Mehtod Get ou Post
     */
    private String Method;
    /**
     * String Chemin  Du repertoire temporaire 
    */
    static String tempPath = System.getenv("TEMP");
    /**
     * String chemin  Des certificats Client 
    */
    static String cheminCertifClient = tempPath+"\\CertificatClient";
    
    static {
    	System.setProperty("javax.net.ssl.trustStore", cheminCertifClient+"\\ksca.ks");
        System.setProperty("javax.net.ssl.trustStorePassword", "x4TRDf4JHY578pth");
        System.setProperty("javax.net.ssl.trustStoreType", "JCEKS");
        System.setProperty("javax.net.ssl.keyStore", cheminCertifClient+"\\ksclient.ks");
        System.setProperty("javax.net.ssl.keyStorePassword", "x4TRDf4JHY578pth");
        System.setProperty("javax.net.ssl.keyStoreType", "JCEKS");
        System.setProperty("javax.net.debug", "ssl");
    }
     /**
         *  Constructeur de la Classe Listener
         *  @param url server Url
         *  @param  path chemain courant 
         *  @param m get or post method
         */
    public Listener(String url,String path,String m) {
        this.url = url;
        this.pathFile=path;
        this.Method = m;
    }
    
    
    public void run() {
        
        
                if(serverOnLine()){
                    try {
                URL urlget = new URL(this.url);
                final HttpsURLConnection connection = (HttpsURLConnection) urlget.openConnection();
                 connection.setHostnameVerifier(new HostnameVerifier() {
            /**
             * Callback invoqué automatiquement si les informations identifiant
             * le serveur, contenues sur le certificat ne correspondent pas
             * au nom d'hôte extrait de l'URL
             */
            public boolean verify(String string, SSLSession sSLSession) {
                try {
                    // pour interroger interactivement l'utilisateur
                    // du client depuis l'entrée standard.
                    BufferedReader console = new BufferedReader(new InputStreamReader(System.in));
                    System.out.println("***!! certificat suspect !!***");
                    // récupération du sujet (description au format X500) lié au serveur
                    X500Principal principal = (X500Principal) connection.getPeerPrincipal();
                    System.out.println("nom serveur: " + principal.getName());
                    System.out.println("ACCEPTER? [o/n]");
                    String rep = console.readLine();
                    if (rep.equalsIgnoreCase("o"))
                    {
                        // provoquera l'acceptation du serveur
                        return true;
                    } else
                    {
                        // provoquera le rejet du serveur
                        return false;
                    }
                    } catch (IOException ioe) {
                        // Problème lors de saisie de la réponse du user
                        // dans le doute le certificat sera rejeté
                        return false;
                    }
                        }
                    });
                
                    if(this.Method.equals("GET")){
                        System.out.println("get");
                        Map<String, List<String>> map = connection.getHeaderFields();
                        String s=connection.getHeaderField(0);
                        String[] result = s.split(" ");
                        String codeResponse = result[1];
                        String tailleFichier = connection.getHeaderField(3);
                        System.out.println(tailleFichier);
                        
                        //System.out.println(connection.getHeaderField(1));
                        if(codeResponse.equals("200")){
                            outputStream = new FileOutputStream(new File(this.pathFile+"\\"+this.url.substring(this.url.indexOf("=")+1, this.url.length())));

                            int read = 0;
                            byte[] bytes = new byte[1024];
                            int somme=0;
                            int pour=0;
                            int taillefile=0;
                            while ((read = connection.getInputStream().read(bytes)) != -1) {
                                somme=somme+read;
                                taillefile=Integer.parseInt(tailleFichier);
                                pour=somme*100;
                                pour=pour/taillefile;
                                ChoixController.getInstance().showMsg(pour+"%");    
                                outputStream.write(bytes, 0, read);
                            }    
                            if(outputStream!=null) outputStream.close();
                            ChoixController.getInstance().showMsg("Fichier reçu");
                        }else{
                            ChoixController.getInstance().showMsg("Fichier n'existe pas sur le serveur");
                        }
                        connection.disconnect();
                        
                        
                    }else if(this.Method.equals("POST")){
                        System.out.println(this.pathFile);
                        File declareresource = new File(this.pathFile);
                        
                        if(declareresource.exists()){
                            if(declareresource.isFile()){
                                try {
                                    Path path = Paths.get(this.pathFile);
                                    byte[] data = Files.readAllBytes(path);
                                    connection.setDoOutput( true );
                                    String ext = this.pathFile.substring(this.pathFile.lastIndexOf(".")+1);
                                    connection.setRequestProperty("Content-Type", ext);
                                    connection.setRequestProperty("Content-Length", ""+data.length);
                                    ChoixController.getInstance().showMsg("Sending of "+data.length+" bytes...");
                                    try (
                                        OutputStream output = connection.getOutputStream();
                                    ) {
                                        // Send normal param.
                                        output.write(data);
                                        output.flush();
                                    }
                                    String s=connection.getHeaderField(0);
                                    String[] result = s.split(" ");
                                    String codeResponse = result[1];
                                    if(codeResponse.equals("200")){
                                        ChoixController.getInstance().showMsg("Fichier envoyé.");
                                    }else{
                                        ChoixController.getInstance().showMsg("erreur d'envoie.");
                                    }
                                }   catch (IOException ex) {
                                    Logger.getLogger(Listener.class.getName()).log(Level.SEVERE, null, ex);
                                    ChoixController.getInstance().showMsg(ex.getStackTrace().toString());
                                }
                            }
                        }
                    }
                    connection.disconnect();
                } catch (MalformedURLException ex) {
                    Logger.getLogger(Listener.class.getName()).log(Level.SEVERE, null, ex);
                    ChoixController.getInstance().showMsg(ex.getStackTrace().toString());
                } catch (IOException ex) {
                    Logger.getLogger(Listener.class.getName()).log(Level.SEVERE, null, ex);
                    ChoixController.getInstance().showMsg(ex.getStackTrace().toString());
                }
                }else{
                    ChoixController.getInstance().showMsg("Serveur Down");
                }
    }

    /**
    * Méthode qui indique si le serveur est en ligne (true) , ou pas (false)
    *  @return  Boolean
    */
    public Boolean serverOnLine(){
        try{
            URL urlget = new URL(this.url);
            final HttpsURLConnection connection = (HttpsURLConnection) urlget.openConnection();
            connection.connect();
            return true;
        }catch(Exception e){
            return false;
        }
    }
    
}
