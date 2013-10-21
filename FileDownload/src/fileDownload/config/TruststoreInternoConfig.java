package fileDownload.config;

/**
 * Datos para usar mi propio truststore en la conexi�n https
 * @author dcenjor
 *
 */
public class TruststoreInternoConfig extends TruststoreConfig{
	public TruststoreInternoConfig() {
		tipoTruststore = "JKS";
		pathTruststore = "/fileDownload/config/truststoreInterno.ks";
		passwordTruststore = "2222";
	}
}
