package fileDownload.config;

/**
 * Datos para usar mi propio truststore en la conexi�n https
 * @author dcenjor
 *
 */
public class TruststoreExternoConfig extends TruststoreConfig{
	public TruststoreExternoConfig() {
		tipoTruststore = null;
		pathTruststore = null;
		passwordTruststore = null;
	}
}
