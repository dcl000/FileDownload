package fileDownload;

import java.io.*;
import java.net.*;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import fileDownload.config.CertificadoConfig;
import fileDownload.config.ProxyConfig;
import fileDownload.config.TruststoreConfig;
import fileDownload.config.TruststoreExternoConfig;
import fileDownload.config.TruststoreInternoConfig;
import fileDownload.config.exceptions.FileDownloadException;
import sun.misc.BASE64Encoder;

public class FileDownload {
	//Autenticación con certificado personal X509
	private CertificadoConfig certificadoConfig = null;
	
	//Datos para usar proxy
	private ProxyConfig proxyConfig = null;
	
	//Datos para usar mi propio truststore
	private TruststoreConfig truststoreExternoConfig = null;
	
	//Datos para usar el truststore de la librería
	private TruststoreConfig truststoreInternoConfig = null;
	
	//Si es true no se comprueba si el certificado del servidor es confiable
	private boolean servidorSiempreConfiable = false;
	
	/**
	 * Descarga de un fichero
	 * @param fAddress URL en la que se encuentra el fichero a descargar
	 * @param destinationDir Directorio de destino para la descarga
	 * @param nombreFichero Nombre con el que se guarda el fichero
	 * @throws FileNotFoundException
	 * @throws MalformedURLException
	 * @throws IOException
	 * @throws Exception
	 */
	public void fileDownload(String fAddress, String destinationDir, String nombreFichero) throws FileNotFoundException, MalformedURLException, IOException, FileDownloadException, Exception {
		int size=1024;
		OutputStream outStream = null;
		InputStream is = null;
		int ByteRead,ByteWritten=0;
		File file = null;
		
		try {
			boolean usarProxy = (proxyConfig!=null);
			boolean usarCertificado = (certificadoConfig!=null);
			boolean usarTruststoreInterno = (truststoreInternoConfig!=null);
			boolean usarTruststoreExterno = (truststoreExternoConfig!=null);
			
			boolean isHttps = fAddress.toUpperCase().startsWith("HTTPS");
			URLConnection uCon = null;
			URL url = null;
			if(isHttps){
				url = new URL(null, fAddress, new sun.net.www.protocol.https.Handler());
			}else{
				url = new URL(null, fAddress, new sun.net.www.protocol.http.Handler());
			}
			file = new File(destinationDir+"/"+nombreFichero);
			outStream = new BufferedOutputStream(new FileOutputStream(file));
			
			if(usarProxy){	//Para conexión a través de proxy
				uCon = getConexionConProxy(isHttps, url, proxyConfig);
			}else{
				uCon = url.openConnection();
			}
			
			if(usarCertificado || usarTruststoreExterno || usarTruststoreInterno || servidorSiempreConfiable){
				if(!isHttps){
					throw new FileDownloadException("Para usar certificados la conexión debe ser https");
				}
				if(servidorSiempreConfiable){
					((HttpsURLConnection)uCon).setSSLSocketFactory(this.getSSLContext(certificadoConfig, null).getSocketFactory());
				}else if(usarTruststoreExterno){
					((HttpsURLConnection)uCon).setSSLSocketFactory(this.getSSLContext(certificadoConfig, truststoreExternoConfig).getSocketFactory());
				}else if(usarTruststoreInterno){
					((HttpsURLConnection)uCon).setSSLSocketFactory(this.getSSLContext(certificadoConfig, truststoreInternoConfig).getSocketFactory());
				}
				
			}
			
			is = uCon.getInputStream();
			byte[] buf = new byte[size];
			while ((ByteRead = is.read(buf)) != -1) {
				outStream.write(buf, 0, ByteRead);
				ByteWritten += ByteRead;
			}
			System.out.println("Fichero descargado en: '"+destinationDir+"/"+nombreFichero+"' (" + ByteWritten/1024+"KB)");
		}
		finally {
			try {
				if(is!=null){
					is.close();
				}
				if(outStream!=null){
					outStream.close();
				}
				if(file!=null && file.length()==0){
					file.delete();
				}
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		
	}
	
	private URLConnection getConexionConProxy(boolean isHttps, URL url, final ProxyConfig proxyConfig) throws IOException{
		URLConnection uCon = null;
		if(isHttps){ //HTTPS
			Authenticator authenticator = new Authenticator() {
		        public PasswordAuthentication getPasswordAuthentication() {
		        	return new PasswordAuthentication(proxyConfig.proxyUsuario, proxyConfig.proxyPassword.toCharArray());
		        }
		    };
		    Authenticator.setDefault(authenticator);
		    uCon = url.openConnection();
		} else {	//HTTP
			Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxyConfig.proxyIP, proxyConfig.proxyPuerto));

			//byte[] credenciales = Base64.encodeBase64(new String(proxyUsuario+":"+proxyPassword).getBytes());
			byte[] credenciales = new BASE64Encoder().encode(new String(proxyConfig.proxyUsuario+":"+proxyConfig.proxyPassword).getBytes()).getBytes();
			
			String auth = new String(credenciales);
		    auth = "Basic " + auth;
		    uCon = (HttpURLConnection)url.openConnection(proxy);
		    uCon.setRequestProperty("Proxy-Authorization",auth);
		}
		return uCon;
	}
	
	private SSLContext getSSLContext(CertificadoConfig certificadoConfig, TruststoreConfig truststoreConfig) throws NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException, KeyStoreException, KeyManagementException, UnrecoverableKeyException{
		KeyManager[] keyManagers = null;
		TrustManager[] trustManagers = null;
		
		if(certificadoConfig!=null){
			keyManagers = getKeyManagers(certificadoConfig);
		}
		
		if(servidorSiempreConfiable){
			trustManagers = getTrustManagersSiempreConfiable();
		}else if(truststoreConfig!=null){
			trustManagers = getTrustManagers(truststoreConfig);
		} 
		
		SSLContext sslContext = SSLContext.getInstance("TLS");
		sslContext.init(keyManagers, trustManagers, null);
		return sslContext;
	}
	
	private KeyManager[] getKeyManagers(CertificadoConfig certConfig) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException{
		//Keystore con el certificado con el que me autentico
		KeyStore ks = KeyStore.getInstance(certConfig.tipoKeystore);
		ks.load(new FileInputStream(new File(certConfig.pathKeystore)), certConfig.passwordKeystore.toCharArray());
		ks.getCertificate(certConfig.aliasKeystoreCert);
		
		KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
		kmf.init(ks, certConfig.passwordKeystore.toCharArray());
		return kmf.getKeyManagers();
	}
	
	private TrustManager[] getTrustManagers(TruststoreConfig trustConfig) throws NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException, KeyStoreException{
		//Truststore con los certificados que quiero que sean de confianza
		KeyStore trustStore = KeyStore.getInstance(trustConfig.tipoTruststore);
		InputStream input = null;
		if(trustConfig instanceof TruststoreInternoConfig){
			input = getClass().getResourceAsStream(trustConfig.pathTruststore);
		}else if(trustConfig instanceof TruststoreExternoConfig){
			input = new FileInputStream(new File(trustConfig.pathTruststore));
		}
		trustStore.load(input, trustConfig.passwordTruststore.toCharArray());
		TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		tmf.init(trustStore);
		return tmf.getTrustManagers();
	}
	
	private TrustManager[] getTrustManagersSiempreConfiable() throws NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException, KeyStoreException{
		TrustManager[] trustAllCerts = new TrustManager[] {
	       new X509TrustManager() {
	          public java.security.cert.X509Certificate[] getAcceptedIssuers() {
	            return null;
	          }
	          public void checkClientTrusted(X509Certificate[] certs, String authType) {  }
	          public void checkServerTrusted(X509Certificate[] certs, String authType) {  }
	       }
	    };
		return trustAllCerts;
	}
	
	/**
	 * Configura la autenticación con certificado X509 sobre TLS 
	 * @param tipoKeystore
	 * @param pathKeystoreCert
	 * @param aliasKeystoreCert
	 * @param passwordKeystore
	 */
	public void setCertificado(String tipoKeystore, String pathKeystoreCert, String aliasKeystoreCert, String passwordKeystore) {
		this.certificadoConfig = new CertificadoConfig();
		this.certificadoConfig.tipoKeystore = tipoKeystore;
		this.certificadoConfig.pathKeystore = pathKeystoreCert;
		this.certificadoConfig.aliasKeystoreCert = aliasKeystoreCert;
		this.certificadoConfig.passwordKeystore = passwordKeystore;
	}
	
	/**
	 * Elimina la configuración del proxy
	 */
	public void removeCertificado(){
		this.certificadoConfig = null;
	}
	
	/**
	 * Añade la configuración de un proxy para realizar la conexión a través de él.
	 * @param proxyIP
	 * @param proxyPuerto
	 * @param proxyUsuario
	 * @param proxyPassword
	 */
	public void setProxy(String proxyIP, int proxyPuerto, String proxyUsuario, String proxyPassword){
		this.proxyConfig = new ProxyConfig();
		this.proxyConfig.proxyIP = proxyIP;
		this.proxyConfig.proxyPuerto = proxyPuerto;
		this.proxyConfig.proxyUsuario = proxyUsuario;
		this.proxyConfig.proxyPassword = proxyPassword;
	}
	
	/**
	 * Elimina la configuración del proxy
	 */
	public void removeProxy(){
		this.proxyConfig = null;
	}
	
	/**
	 * Para usar como almacén de certificados confiables un truststore localizado en sistema de ficheros
	 * @param tipoTruststore
	 * @param pathTruststore
	 * @param passwordTruststore
	 */
	public void setTruststore(String tipoTruststore, String pathTruststore, String passwordTruststore) {
		removeTruststore();
		this.truststoreExternoConfig = new TruststoreExternoConfig();
		this.truststoreExternoConfig.tipoTruststore = tipoTruststore;
		this.truststoreExternoConfig.pathTruststore = pathTruststore;
		this.truststoreExternoConfig.passwordTruststore = passwordTruststore;
	}
	
	/**
	 * Para usar como almacén de certificados confiables el propio truststore de esta librería
	 */
	public void setTruststore() {
		removeTruststore();
		this.truststoreInternoConfig = new TruststoreInternoConfig();
	}
	
	/**
	 * Elimina la configuración relativa al truststore
	 */
	public void removeTruststore(){
		this.truststoreExternoConfig = null;
		this.truststoreInternoConfig = null;
	}
	
	/**
	 * Para indicar que no verifique si el certificado del servidor es confiable. 
	 * La conexión se realizará independientemente de si el certificado es confiable o no.
	 */
	public void setServidorSiempreConfiable(){
		this.servidorSiempreConfiable = true;
	}
	
	/**
	 * Elimina la configuración relativa al truststore
	 */
	public void removeServidorSiempreConfiable(){
		servidorSiempreConfiable = false;
	}
	
}