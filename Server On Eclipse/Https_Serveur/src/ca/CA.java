package ca;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.security.auth.x500.X500Principal;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;
import x509.PKIValidator;

/**
 * Une classe implémentant une autorité de certification
 * @author P. Guichet & J. Lepagnot
 */
public class CA {

	// Le DN du CA
	private static final String DN = "CN=RootCA, OU=M2, O=miage, L=Mulhouse, ST=68093, C=FR";
	// L'alias permettant la récupération du certificat autosigné du CA
	private static final String ALIAS = "miageCA";
	// Le chemin du fichier contenant le keystore du CA
	private static final String CA_KS_FILE = "ksca.ks";
	// L'OID de l'algorithme SHA-1
	private static final String SHA1_OID = "1.3.14.3.2.26";
	// L'OID de l'algorithme SHA1withRSA
	private static final String SHA1_WITH_RSA_OID = "1.2.840.113549.1.1.5";
	// L'OID de l'extension Basic Constraint
	private static final String BASIC_CONSTRAINT_OID = "2.5.29.19";
	// L'OID de l'extension SubjectKeyIdentifier
	private static final String SUBJECT_KEY_IDENTIFIER_OID = "2.5.29.14";
	// L'OID de l'extension keyUsage
	private static final String KEY_USAGE_OID = "2.5.29.15";
	// L'OID de l'extension extKeyUsage
	private static final String EXT_KEY_USAGE_OID = "2.5.29.37";
	// L'OID de l'extension altName
	private static final String SUBJECT_ALT_NAME_OID = "2.5.29.17";
	// La valeur de l'extension keyUsage pour une autorité racine
	private static final int CA_KEY_USAGE_VALUE =
	    KeyUsage.digitalSignature | KeyUsage.nonRepudiation | KeyUsage.cRLSign | KeyUsage.keyCertSign;
	// La valeur de l'extension keyUsage pour un certificat de serveur
	private static final int SV_KEY_USAGE_VALUE =
	    KeyUsage.keyAgreement | KeyUsage.keyEncipherment | KeyUsage.digitalSignature;
	// Délimiteur début certificat
	private static final String CERT_BEGIN = "-----BEGIN CERTIFICATE-----\n";
	// Délimiteur fin certificat
	private static final String CERT_END = "\n-----END CERTIFICATE-----";

	// Le certificat du CA
	private Certificate caCert;
	// La clé privée du CA
	private PrivateKey caPk;

	/**
	 * Construction d'une instance de la classe
	 * @param passwd le mot de passe protégeant le keystore du CA
	 * @throws GeneralSecurityException si la fabrication/récupération du certificat du CA échoue
	 * @throws IOException si une erreur d'entrée-sortie se produit,
	 * par exemple sérialisation du keystore corrompue
	 */
	public CA(char[] passwd,String cheminCa) throws GeneralSecurityException, IOException {
		KeyStore ksCa = KeyStore.getInstance("JCEKS");
		File caDir = new File(cheminCa+CA_KS_FILE);
		if (caDir.exists()) {
			// Le keystore existe déjà il suffit de le charger
			ksCa.load(new BufferedInputStream(new FileInputStream(caDir)), passwd);
			// puis de récupérer le certificat du CA et la clé privée associée
			this.caCert = ksCa.getCertificate(ALIAS);
			this.caPk = (PrivateKey) ksCa.getKey(ALIAS, passwd);
		} else {
			// le keystore n'existe pas il faut construire la paire de clés publique, privée
			// et empaqueter la clé publique dans un certificat X509 autosigné
			installCA(ksCa, passwd, caDir);
		}
	}

	/**
	 * Méthode d'aide pour la fabrication d'une CA qui n'existe pas encore 
	 * @param ks le keystore du CA
	 * @param passwd le mot de passe qui protège le keystore
	 * @param caDir le fichier où sera sérialisé le keystore
	 * @throws GeneralSecurityException si la fabrication/récupération du certificat du CA échoue
	 * @throws IOExceptionsi une erreur d'entrée-sortie se produit, 
	 * par exemple sérialisation du keystore corrompue
	 */
	private void installCA(KeyStore ks, char[] passwd, File caDir)
		throws GeneralSecurityException, IOException {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);
		KeyPair caKp = kpg.generateKeyPair();
		this.caPk = caKp.getPrivate();
		X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
		// le numéro de série de ce certificat
		certGen.setSerialNumber(BigInteger.ONE);
		// le nom de l'émetteur (et du sujet)
		X500Principal caDn = new X500Principal(DN);
		certGen.setIssuerDN(caDn);
		// le nom du sujet
		certGen.setSubjectDN(caDn);
		Calendar calendar = Calendar.getInstance();
		// le début de la période de validité
		Date notBefore = calendar.getTime();
		certGen.setNotBefore(notBefore);
		calendar.set(2012, 12, 31);
		// la fin de la période de validité
		certGen.setNotAfter(calendar.getTime());
		// la clé publique enveloppée dans le certificat
		certGen.setPublicKey(caKp.getPublic());
		// l'algorithme de signature
		certGen.setSignatureAlgorithm(SHA1_WITH_RSA_OID);
		// extension définissant l'usage de la clé
		certGen.addExtension(
			KEY_USAGE_OID, false, new KeyUsage(CA_KEY_USAGE_VALUE));
		// extension BasicConstraint
		certGen.addExtension(
			BASIC_CONSTRAINT_OID, true, new BasicConstraints(Integer.MAX_VALUE));
		// extension subjectKeyIdentifier
		certGen.addExtension(
			SUBJECT_KEY_IDENTIFIER_OID, 
			false, 
			new SubjectKeyIdentifierStructure(caKp.getPublic()));
		this.caCert = certGen.generate(this.caPk);
		ks.load(null, passwd);
		// Insérer le certificat dans le keystore
		ks.setCertificateEntry(ALIAS, caCert);
		// Insérer la clé privée associée dans le keystore
		KeyStore.PrivateKeyEntry pke = 
			new KeyStore.PrivateKeyEntry(caPk, new Certificate[]{this.caCert});
		ks.setEntry(ALIAS, pke, new KeyStore.PasswordProtection(passwd));
		// Sauvegarder le keystore nouvellement créé
		OutputStream out = new BufferedOutputStream(new FileOutputStream(caDir));
		ks.store(out, passwd);
	}
	
	/**
	 * Génération d'un certificat pour l'identification d'un serveur
	 * @param dn le nom distingué du serveur
	 * @param altName le nom alternatif du serveur
	 * @param pk la clé publique devant être enrobée dans le certificat
	 * @return un certificat (norme X509 v3) empaquettan la clé publique pk
	 * @throws GeneralSecurityException si la fabrication du certificat échoue
	 * @throws IOException si la fabrication du numéro de série échoue 
	 */
	X509Certificate generateServerCertificate(String dn, String altName, PublicKey pk)
		throws GeneralSecurityException, IOException {
		X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
		// le numéro de série de ce certificat
		certGen.setSerialNumber(SerialIdGenerator.generate());
		// le nom de l'émetteur
		X500Principal caDnI = new X500Principal(DN);
		certGen.setIssuerDN(caDnI);
		// le nom du sujet
		X500Principal caDnS = new X500Principal(dn);
		certGen.setSubjectDN(caDnS);
		Calendar calendar = Calendar.getInstance();
		// le début de la période de validité
		Date notBefore = calendar.getTime();
		certGen.setNotBefore(notBefore);
		calendar.add(Calendar.YEAR, 2);
		// la fin de la période de validité
		certGen.setNotAfter(calendar.getTime());
		// la clé publique enveloppée dans le certificat
		certGen.setPublicKey(pk);
		// l'algorithme de signature
		certGen.setSignatureAlgorithm(SHA1_WITH_RSA_OID);
		// extension définissant l'usage de la clé
		certGen.addExtension(
			KEY_USAGE_OID, false, new KeyUsage(SV_KEY_USAGE_VALUE));
		// extension définissant le nom alternatif du serveur
		certGen.addExtension(
			SUBJECT_ALT_NAME_OID,
                        false,
                        new GeneralNames(new GeneralName(GeneralName.dNSName, altName)));
		// extension subjectKeyIdentifier
		certGen.addExtension(
			SUBJECT_KEY_IDENTIFIER_OID, 
			false, 
			new SubjectKeyIdentifierStructure(pk));
		return certGen.generate(this.caPk);
	}
		
	/**
	 * Exportation du certificat du CA en DER encodé Base64
	 * @param file le fichier où exporter le certificat
	 * @param cert le certificat à exporter
	 * @throws GeneralSecurityException si l'encodage DER échoue
	 * @throws IOException si l'exportation échoue
	 */
    public static void exportCertificate(File file, Certificate cert)
    	throws GeneralSecurityException, IOException {
        try (OutputStream out = new BufferedOutputStream(new FileOutputStream(file))) {
            out.write(CERT_BEGIN.getBytes("UTF-8"));
            out.write(Base64.encodeBase64Chunked(cert.getEncoded()));
            out.write(CERT_END.getBytes("UTF-8"));
        }
    }
		
	/**
	 * Exportation du certificat du CA en DER encodé base64
	 * @param fileName le nom du fichier où exporter le certificat
	 * @param cert le certificat à exporter
	 * @throws GeneralSecurityException si l'encodage DER échoue
	 * @throws IOException si l'exportation échoue
	 */
	public static void exportCertificate(String fileName, Certificate cert) 
		throws GeneralSecurityException, IOException {
		exportCertificate(new File(fileName), cert);
	}

    /**
     * Démonstration de la classe.
     * @param args
     */
    public static void main(String[] args) {
        try {
            // Pour pouvoir utiliser l'API BouncyCastle au travers du mécanisme standard du JCE
            Security.addProvider(new BouncyCastleProvider());
            // Instanciation d'une CA depuis un fichier keystore, s'il existe
            String ch=new File("").getAbsolutePath();
            CA ca = new CA("x4TRDf4JHY578pth".toCharArray(),ch);
            // Génération d'une paire de clés pour un certificat serveur
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair caKp = kpg.generateKeyPair();
            // Génération du certificat serveur
            PublicKey pk = caKp.getPublic();
            X509Certificate srvCert = ca.generateServerCertificate(
                    "CN=localhost, OU=FST, O=UHA, L=Mulhouse, ST=68093, C=FR",
                    "localhost",
                    pk);

            /*** DEBUT DU CODE GENERANT LE KEYSTORE DU SERVEUR TD4 ***/
            KeyStore ks = KeyStore.getInstance("JCEKS");
            // ks.load(new FileInputStream(CA_KS_FILE), "x4TRDf4JHY578pth".toCharArray());
            ks.load(null, "x4TRDf4JHY578pth".toCharArray());
            // Insérer le certificat dans le keystore
            ks.setCertificateEntry("localhost", srvCert);
            // Insérer la clé privée associée dans le keystore
            KeyStore.PrivateKeyEntry pke = 
                    new KeyStore.PrivateKeyEntry(caKp.getPrivate(), new Certificate[]{srvCert});
            ks.setEntry("localhost", pke, new KeyStore.PasswordProtection("x4TRDf4JHY578pth".toCharArray()));
            // Sauvegarder le keystore nouvellement créé
            File srvDir = new File("kssrv.ks");
            OutputStream out = new BufferedOutputStream(new FileOutputStream(srvDir));
            ks.store(out, "x4TRDf4JHY578pth".toCharArray());
            /*** FIN DU CODE GENERANT LE KEYSTORE DU SERVEUR TD4 ***/

            // Exportation du certification du serveur
            CA.exportCertificate("srv.cer", srvCert);
            // Exportation du certification du CA
            CA.exportCertificate("ca.cer", ca.caCert);
            // Création d'un chemin de certification pour srvCert
            CertificateFactory factory = CertificateFactory.getInstance("X509");
            List list = new ArrayList();
            list.add(srvCert);
            CertPath cp = factory.generateCertPath(list);
            byte[] encoded = cp.getEncoded("PKCS7");
            try (OutputStream out2 = new BufferedOutputStream(new FileOutputStream("srv.p7b"))) {
                out2.write(encoded);
            }
            // Vérification de ce chemin de certification en utilisant caCert
            PKIValidator pkiV = new PKIValidator(new String[]{"ca.cer"});
            pk = pkiV.validate("srv.p7b", "PKCS7");
            // Affichage de la clé publique du serveur
            System.out.println(pk);
        } catch (GeneralSecurityException | IOException ex) {
            Logger.getLogger(CA.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    
    
    //il faut utiliser le mm ca pour que le serveur reconnait le client
	public static void generateCertifServeur(String urlServeur, String cheminCertifServeur) {
		System.out.println("Url serveur : "+urlServeur+" \n Chemin Certificat Serveur : "+cheminCertifServeur);
		try {
            // Pour pouvoir utiliser l'API BouncyCastle au travers du mécanisme standard du JCE
            Security.addProvider(new BouncyCastleProvider());
            // Instanciation d'une CA depuis un fichier keystore, s'il existe
            
            CA ca = new CA("x4TRDf4JHY578pth".toCharArray(),cheminCertifServeur);
            // Génération d'une paire de clés pour un certificat serveur
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair caKp = kpg.generateKeyPair();
            // Génération du certificat serveur
            PublicKey pk = caKp.getPublic();
            X509Certificate srvCert = ca.generateServerCertificate(
                    "CN="+urlServeur+", OU=FST, O=UHA, L=Mulhouse, ST=68093, C=FR",
                    urlServeur,
                    pk);

            /*** DEBUT DU CODE GENERANT LE KEYSTORE DU SERVEUR TD4 ***/
            KeyStore ks = KeyStore.getInstance("JCEKS");
            // ks.load(new FileInputStream(CA_KS_FILE), "x4TRDf4JHY578pth".toCharArray());
            ks.load(null, "x4TRDf4JHY578pth".toCharArray());
            // Insérer le certificat dans le keystore
            ks.setCertificateEntry(urlServeur, srvCert);
            // Insérer la clé privée associée dans le keystore
            KeyStore.PrivateKeyEntry pke = 
                    new KeyStore.PrivateKeyEntry(caKp.getPrivate(), new Certificate[]{srvCert});
            ks.setEntry(urlServeur, pke, new KeyStore.PasswordProtection("x4TRDf4JHY578pth".toCharArray()));
            // Sauvegarder le keystore nouvellement créé
            File srvDir = new File(cheminCertifServeur+"kssrv.ks");
            OutputStream out = new BufferedOutputStream(new FileOutputStream(srvDir));
            ks.store(out, "x4TRDf4JHY578pth".toCharArray());
            /*** FIN DU CODE GENERANT LE KEYSTORE DU SERVEUR TD4 ***/

            // Exportation du certification du serveur
            CA.exportCertificate(cheminCertifServeur+"srv.cer", srvCert);
            // Exportation du certification du CA
            CA.exportCertificate(cheminCertifServeur+"ca.cer", ca.caCert);
            // Création d'un chemin de certification pour srvCert
            CertificateFactory factory = CertificateFactory.getInstance("X509");
            List list = new ArrayList();
            list.add(srvCert);
            CertPath cp = factory.generateCertPath(list);
            byte[] encoded = cp.getEncoded("PKCS7");
            try (OutputStream out2 = new BufferedOutputStream(new FileOutputStream(cheminCertifServeur+"srv.p7b"))) {
                out2.write(encoded);
            }
            // Vérification de ce chemin de certification en utilisant caCert
            PKIValidator pkiV = new PKIValidator(new String[]{cheminCertifServeur+"ca.cer"});
            pk = pkiV.validate(cheminCertifServeur+"srv.p7b", "PKCS7");
            // Affichage de la clé publique du serveur
            System.out.println(pk);
        } catch (GeneralSecurityException | IOException ex) {
            Logger.getLogger(CA.class.getName()).log(Level.SEVERE, null, ex);
        }
		
	}
	
	
	//il faut utiliser le mm ca pour que le serveur reconnait le client
	public static void generateCertifClient(String urlServeur, String cheminCertifClient,String cheminCertifServeur) {
		System.out.println(urlServeur+" / "+cheminCertifClient);
		try {
            // Pour pouvoir utiliser l'API BouncyCastle au travers du mécanisme standard du JCE
            Security.addProvider(new BouncyCastleProvider());
            // Instanciation d'une CA depuis un fichier keystore, s'il existe
            String ch=new File("").getAbsolutePath();
            CA ca = new CA("x4TRDf4JHY578pth".toCharArray(),cheminCertifServeur);
            // Génération d'une paire de clés pour un certificat serveur
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair caKp = kpg.generateKeyPair();
            // Génération du certificat serveur
            PublicKey pk = caKp.getPublic();
            X509Certificate clientCert = ca.generateServerCertificate(
                    "CN="+urlServeur+", OU=FST, O=UHA, L=Mulhouse, ST=68093, C=FR",
                    urlServeur,
                    pk);

            /*** DEBUT DU CODE GENERANT LE KEYSTORE DU SERVEUR TD4 ***/
            KeyStore ks = KeyStore.getInstance("JCEKS");
            // ks.load(new FileInputStream(CA_KS_FILE), "x4TRDf4JHY578pth".toCharArray());
            ks.load(null, "x4TRDf4JHY578pth".toCharArray());
            // Insérer le certificat dans le keystore
            ks.setCertificateEntry(urlServeur, clientCert);
            // Insérer la clé privée associée dans le keystore
            KeyStore.PrivateKeyEntry pke = 
                    new KeyStore.PrivateKeyEntry(caKp.getPrivate(), new Certificate[]{clientCert});
            ks.setEntry(urlServeur, pke, new KeyStore.PasswordProtection("x4TRDf4JHY578pth".toCharArray()));
            // Sauvegarder le keystore nouvellement créé
            File srvDir = new File(cheminCertifClient+"ksclient.ks");
            OutputStream out = new BufferedOutputStream(new FileOutputStream(srvDir));
            ks.store(out, "x4TRDf4JHY578pth".toCharArray());
            /*** FIN DU CODE GENERANT LE KEYSTORE DU SERVEUR TD4 ***/

            // Exportation du certification du serveur
            CA.exportCertificate(cheminCertifClient+"client.cer", clientCert);
            // Exportation du certification du CA
            CA.exportCertificate(cheminCertifClient+"ca.cer", ca.caCert);
            // Création d'un chemin de certification pour srvCert
            CertificateFactory factory = CertificateFactory.getInstance("X509");
            List list = new ArrayList();
            list.add(clientCert);
            CertPath cp = factory.generateCertPath(list);
            byte[] encoded = cp.getEncoded("PKCS7");
            try (OutputStream out2 = new BufferedOutputStream(new FileOutputStream(cheminCertifClient+"client.p7b"))) {
                out2.write(encoded);
            }
            // Vérification de ce chemin de certification en utilisant caCert
            PKIValidator pkiV = new PKIValidator(new String[]{cheminCertifClient+"ca.cer"});
            pk = pkiV.validate(cheminCertifClient+"client.p7b", "PKCS7");
            // Affichage de la clé publique du serveur
            System.out.println(pk);
            
            
            InputStream inStream = null;
        	OutputStream outStream = null;
        	try{
     
        	    File file1 =new File(cheminCertifServeur+""+CA_KS_FILE);
        	    File file2 =new File(cheminCertifClient+""+CA_KS_FILE);
     
        	    inStream = new FileInputStream(file1);
        	    outStream = new FileOutputStream(file2); // for override file content
        	    
        	    byte[] buffer = new byte[1024];
     
        	    int length;
        	    while ((length = inStream.read(buffer)) > 0){
        	    	outStream.write(buffer, 0, length);
        	    }
     
        	    if (inStream != null)inStream.close();
        	    if (outStream != null)outStream.close();
     
        	    System.out.println("File Copied..");
        	}catch(IOException e){
        		e.printStackTrace();
        	}
            
        } catch (GeneralSecurityException | IOException ex) {
            Logger.getLogger(CA.class.getName()).log(Level.SEVERE, null, ex);
        }
		
	}
}
