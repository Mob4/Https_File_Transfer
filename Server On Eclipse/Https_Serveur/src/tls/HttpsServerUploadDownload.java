package tls;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;

import ca.CA;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.util.concurrent.Executor;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;

/**
 * 
 * Serveur de fichiers s�curis� par le protocole HTTPS.
 * Date: Janvier 8-2017
 * @author Groupe7
 *@version 1.0
 *
 */
public class HttpsServerUploadDownload {
    ////////////////////////////////////////////////////////
    // Initialisation des propri�t�s syst�mes n�cessaires 
    // � l'�tablissement d'un contexte SSL	
	static String tempPath = System.getenv("TEMP");
	static String cheminCertifServeur = tempPath+"\\CertificatServeur";
	static String cheminCertifClient = tempPath+"\\CertificatClient";
	static String RepDoc = "fileserver";
	
	static {
    	System.setProperty("javax.net.ssl.trustStore", cheminCertifServeur+"\\ksca.ks");
        System.setProperty("javax.net.ssl.trustStorePassword", "x4TRDf4JHY578pth");
        System.setProperty("javax.net.ssl.trustStoreType", "JCEKS");
        
        System.setProperty("javax.net.ssl.keyStore", cheminCertifServeur+"\\kssrv.ks");
        System.setProperty("javax.net.ssl.keyStorePassword", "x4TRDf4JHY578pth");
        System.setProperty("javax.net.ssl.keyStoreType", "JCEKS");
        
        System.setProperty("javax.net.debug", "all");
    }

	  /**
     *
     * le traiteur des requetes
     * Date: Janvier 8-2017
     * @author GROUPE 7
     * @version 1.0
     *
     */
   public static class RequestHandler implements HttpHandler {

        
        /**
         * M�thode de gestion des requ�tes
         * @param he l'objet encapsulant la requ�te et la r�ponse
         * @throws IOException si le traitement de la requ�te ou de la r�ponse �choue
         */
        @Override
        public void handle(HttpExchange he) throws IOException {
            // r�cup�ration des param�tres de requ�tes
        	
        	String query = he.getRequestURI().getQuery();
            String req = he.getRequestMethod();
            
            
            // r�cup�ration des en-t�tes de la r�ponse HTTP
            Headers responseHeaders = he.getResponseHeaders();
            responseHeaders.set("Content-Type", "text/html");
            
            if (query != null) {
            	String[] result = query.split("=");
            	String sAction = result[0];
            	String FileName = result[1];
            	
            	
            	if(sAction.equals("download") )
            	{
            		//traiter download
            		File declareresource = new File(new File("").getAbsolutePath()+"\\"+RepDoc+"\\"+FileName);
            		if(declareresource.exists()){
        				if(declareresource.isFile())
    					{
        					int type_file = 0;
        					Path path = Paths.get(new File("").getAbsolutePath()+"\\"+RepDoc+"\\"+FileName);
                    		byte[] data = Files.readAllBytes(path);
                    		System.out.println(data.length);
                    		he.sendResponseHeaders(200, data.length);
                            try (OutputStream out = he.getResponseBody()) {
                                out.write(data);
                                out.flush();
                            }
    					}
            		}else{
            			he.sendResponseHeaders(404, 55);
            		}
            		
            	}else if(sAction.equals("upload"))
            	{
            		//traiter upload
            		Headers reqHeaders = he.getRequestHeaders();
            		String length = reqHeaders.getFirst("Content-Length");
            		String type = reqHeaders.getFirst("Content-Type");
            		if (length != null) {
            		    OutputStream outputStream = new FileOutputStream(new File(new File("").getAbsolutePath()+"\\"+RepDoc+"\\"+FileName));

                        int read = 0;
                        byte[] bytes = new byte[1024];
                        while ((read = he.getRequestBody().read(bytes)) != -1) {
                            outputStream.write(bytes, 0, read);
                    	}
                        if(outputStream!=null) outputStream.close();
                        he.sendResponseHeaders(200,55);
            		}
            		he.sendResponseHeaders(400,55);
            	}else{
            		//traiter exception
            		System.out.println(sAction);
            	}
            }
        }
    }

   /**
    *  Classe g�rant l'ordonnancement des r�actions aux requ�tes
    * Ici un nouveau thread est cr�� pour le traitement de chaque requ�te
    * @author GROUPE 7
    *
    */
    public static class ThreadPerTaskExecutor implements Executor {

        /**
         * M�thode impl�mentant la strat�gie d'ex�cution d'une nouvelle requ�te
         * @param command le Runnable � ex�cuter
         */
        @Override
        public void execute(Runnable command) {
            // Instancier un nouveau thread d�di� � l'ex�cution de ce Runnable
            // et le d�marrer
            new Thread(command).start();
        }
    }
    // le contexte du service
    /**
     * Context de notre service o� se trouve les fichiers du Serveur
     */
    private static final String CONTEXT = "/"+RepDoc;
    // le serveur HTTPS
    /**
     * HTTPS Server OBJECT com.sun.net.httpserver.HttpsServer;
     */
    private HttpsServer server;

    /**
     * Cr�ation d'une instance du serveur
     * @param host le nom de l'h�te h�bergeant le service
     * @param port le num�ro de port associ� au service hello
     * @throws IOException si la cr�ation du serveur �choue
     */
    public HttpsServerUploadDownload(String host, int port) throws IOException, GeneralSecurityException {
        this.server = HttpsServer.create(new InetSocketAddress(host, port), 0);
        // Association du contexte au handler charg� de traiter les requ�tes
        
        server.createContext("/"+RepDoc, new RequestHandler());
        
        SSLContext ssl=SSLContext.getDefault();
        
        HttpsConfigurator configurator=new HttpsConfigurator(ssl) {
            public void configure (HttpsParameters params) 
            {
                SSLContext context; 
                SSLParameters sslparams;

                context=getSSLContext();
                sslparams=context.getDefaultSSLParameters();
                sslparams.setNeedClientAuth(true);
                params.setSSLParameters(sslparams);
            }
        }; 
        
        // Configuration du contexte SSL
        ((HttpsServer)this.server).setHttpsConfigurator(configurator);
        //this.server.setHttpsConfigurator(new HttpsConfigurator(SSLContext.getDefault();));
        //this.server.setNeedClientAuth(true);
        // Configuration de l'ex�cuteur traitant les r�ponses
        this.server.setExecutor(new ThreadPerTaskExecutor());
        
        // Lancement du serveur
        this.server.start();
        System.out.println("En attente de connection!..");
    }

    /**
     * Pr�paration du wrokspace " les repertoire des certificats Serveur et Client et le r�pertoire fileServer
     * G�n�ration des Certificats Serveur
     * G�n�ration des Certificats Client
     * Instanciation du Serveur 
     * @param args les �ventuels arguments transmis en ligne de commande
     */
    public static void main(String[] args) {
        try {
        	String urlServeur = "localhost";
        	
        	//creer le repertoire qui contient les certificats du serveur
        	File repServ = new File(cheminCertifServeur);
            if(!repServ.exists())
            	repServ.mkdir();
            
            //creer le repertoire qui contient les certificats du client
        	File repClient = new File(cheminCertifClient);
            if(!repClient.exists())
            	repClient.mkdir();
            
            //creer le repertoire qui contient les documents echang�s entre le serveur et le client
        	
            File rep = new File(RepDoc);
            if(!rep.exists())
            	rep.mkdir();
            
	    	//generer le certificat du serveur
	        CA.generateCertifServeur(urlServeur,cheminCertifServeur+"\\");
	    	//generer le certificat du client
	    	CA.generateCertifClient(urlServeur,cheminCertifClient+"\\",cheminCertifServeur+"\\");
	    	
            //lancer le serveur
            HttpsServerUploadDownload httpsHelloServer = new HttpsServerUploadDownload(urlServeur, 7878);
        } catch (IOException | GeneralSecurityException ex) {
            Logger.getLogger(HttpsServerUploadDownload.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
}
