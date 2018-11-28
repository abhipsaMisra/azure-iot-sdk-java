// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

package samples.com.microsoft.azure.sdk.iot;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.microsoft.azure.sdk.iot.provisioning.service.ProvisioningServiceClient;
import com.microsoft.azure.sdk.iot.provisioning.service.helpers.ProvisioningServiceClientHelper;
import com.microsoft.azure.sdk.iot.provisioning.service.implementation.ProvisioningServiceClientImpl;
import com.microsoft.azure.sdk.iot.provisioning.service.models.AttestationMechanism;
import com.microsoft.azure.sdk.iot.provisioning.service.models.IndividualEnrollment;
import com.microsoft.azure.sdk.iot.provisioning.service.models.InitialTwin;
import com.microsoft.azure.sdk.iot.provisioning.service.models.InitialTwinProperties;
import com.microsoft.azure.sdk.iot.provisioning.service.models.ProvisioningServiceErrorDetailsException;
import com.microsoft.azure.sdk.iot.provisioning.service.models.QuerySpecification;
import com.microsoft.azure.sdk.iot.provisioning.service.models.TpmAttestation;
import com.microsoft.azure.sdk.iot.provisioning.service.models.TwinCollection;
import com.microsoft.rest.RestClient;
import com.microsoft.rest.ServiceResponseBuilder;
import com.microsoft.rest.credentials.ServiceClientCredentials;
import com.microsoft.rest.serializer.JacksonAdapter;
import okhttp3.OkHttpClient;
import okio.Buffer;

/**
 * Create, get, query, and delete an individual enrollment on the Microsoft
 * Azure IoT Hub Device Provisioning Service
 */
public class ServiceEnrollmentSample
{
	/*
	 * Details of the Provisioning.
	 */
	private static final String PROVISIONING_CONNECTION_STRING = "";
	// private static final String PROVISIONING_CONNECTION_STRING =
	// "";
	private static final String DPS_BASE_URL = "t";

	private static final String REGISTRATION_ID = "testtpmregistration";
	private static final String TPM_ENDORSEMENT_KEY = "";

	// Optional parameters
	private static final String IOTHUB_HOST_NAME = "t";
	private static final String DEVICE_ID = "myJavaDevice";
	// private static final ProvisioningStatus PROVISIONING_STATUS =
	// ProvisioningStatus.ENABLED;
	private static final String PROVISIONING_STATUS = "enabled";
	private static final String TPM_ATTESTATION = "tpm";

	public static void main(String[] args) throws ProvisioningServiceErrorDetailsException, JsonProcessingException
	{
		System.out.println("Starting sample...");

		ObjectWriter objectWriter = new ObjectMapper().writer().withDefaultPrettyPrinter();

		// *********************************** Create a Provisioning Service Client
		// ************************************
		ServiceClientCredentials credentials = ProvisioningServiceClientHelper
				.createCredentialsFromConnectionString(PROVISIONING_CONNECTION_STRING);

		// ******************************** Injecting Fiddler cert trust
		// **********************************************
		
		  X509TrustManager trustManager; SSLSocketFactory sslSocketFactory;
		  
		try
		{
			trustManager = trustManagerForCertificates(trustedCertificatesInputStream());
			SSLContext sslContext = SSLContext.getInstance("TLS");
			sslContext.init(null, new TrustManager[] { trustManager }, null);
			sslSocketFactory = sslContext.getSocketFactory();
		}
		catch (GeneralSecurityException e)
		{
			throw new RuntimeException(e);
		}

		OkHttpClient.Builder httpClientBuilder = new OkHttpClient.Builder().sslSocketFactory(sslSocketFactory,
				trustManager);
		 

		// ******************************** Injecting Fiddler cert trust end
		// **********************************************

		RestClient simpleRestClient = new RestClient.Builder().withBaseUrl(DPS_BASE_URL).withCredentials(credentials)
				.withResponseBuilderFactory(new ServiceResponseBuilder.Factory())
				.withSerializerAdapter(new JacksonAdapter()).build();

		ProvisioningServiceClient provisioningServiceClient = new ProvisioningServiceClientImpl(simpleRestClient);

		// ******************************** Create a new individualEnrollment config
		// **********************************
		System.out.println("\nCreate a new individualEnrollment...");
		TpmAttestation attestation = new TpmAttestation().withEndorsementKey(TPM_ENDORSEMENT_KEY);
		AttestationMechanism attestationMechanism = new AttestationMechanism().withType(TPM_ATTESTATION)
				.withTpm(attestation);
		Map<String, Object> desiredProperties = new HashMap<String, Object>()
		{
			{
				put("Brand", "Contoso");
				put("Model", "SSC4");
				put("Color", "White");
			}
		};
		IndividualEnrollment individualEnrollment = new IndividualEnrollment().withRegistrationId(REGISTRATION_ID)
				.withAttestation(attestationMechanism);

		// The following parameters are optional. Remove it if you don't need.
		InitialTwin initialTwin = new InitialTwin().withProperties(new InitialTwinProperties()
				.withDesired(new TwinCollection().withAdditionalProperties(desiredProperties)));
		individualEnrollment.withDeviceId(DEVICE_ID).withIotHubHostName(IOTHUB_HOST_NAME)
				.withProvisioningStatus(PROVISIONING_STATUS).withInitialTwin(initialTwin);

		// ************************************ Create the individualEnrollment
		// *************************************
		System.out.println("\nAdd new individualEnrollment...");
		IndividualEnrollment individualEnrollmentResult = provisioningServiceClient
				.createOrUpdateIndividualEnrollment(REGISTRATION_ID, individualEnrollment);
		System.out.println("\nIndividualEnrollment created with success...");
		System.out.println(objectWriter.writeValueAsString(individualEnrollmentResult));

		// ************************************* Get info of individualEnrollment
		// *************************************
		System.out.println("\nGet the individualEnrollment information...");
		IndividualEnrollment getIndividualEnrollmentResult = provisioningServiceClient
				.getIndividualEnrollment(REGISTRATION_ID);
		System.out.println(objectWriter.writeValueAsString(getIndividualEnrollmentResult));

		// ********************************* Update the info of individualEnrollment
		// ***********************************
		System.out.println("\nUpdate the individualEnrollment information...");
		desiredProperties.put("Color", "Glace white");
		initialTwin.withProperties(new InitialTwinProperties()
				.withDesired(new TwinCollection().withAdditionalProperties(desiredProperties)));
		getIndividualEnrollmentResult.withInitialTwin(initialTwin);
		IndividualEnrollment updateIndividualEnrollmentResult = provisioningServiceClient
				.createOrUpdateIndividualEnrollment(REGISTRATION_ID, getIndividualEnrollmentResult,
						getIndividualEnrollmentResult.etag());
		System.out.println("\nIndividualEnrollment updated with success...");
		System.out.println(objectWriter.writeValueAsString(updateIndividualEnrollmentResult));

		// ************************************ Query info of individualEnrollment
		// ************************************
		System.out.println("\nCreate a query for enrollments...");
		QuerySpecification querySpecification = new QuerySpecification().withQuery("SELECT * FROM ENROLLMENTS");
		List<IndividualEnrollment> queryResult = provisioningServiceClient
				.queryIndividualEnrollments(querySpecification);

		for (IndividualEnrollment eachEnrollment : queryResult)
		{
			System.out.println(objectWriter.writeValueAsString(eachEnrollment));
		}

		// *********************************** Delete info of individualEnrollment
		// ************************************
		System.out.println("\nDelete the individualEnrollment...");
		provisioningServiceClient.deleteIndividualEnrollment(REGISTRATION_ID);
	}

	
	private static InputStream trustedCertificatesInputStream()
	{
		// PEM files for root certificates of Comodo and Entrust. These two CAs are
		// sufficient to view
		// https://publicobject.com (Comodo) and https://squareup.com (Entrust). But
		// they aren't
		// sufficient to connect to most HTTPS sites including https://godaddy.com and
		// https://visa.com.
		// Typically developers will need to get a PEM file from their organization's
		// TLS administrator.
		String fiddlerCertificationAuthority = "" + "-----BEGIN CERTIFICATE-----\r\n"
				+ "MIIDsjCCApqgAwIBAgIQFKYWyExsxbVGS2z17DY7dzANBgkqhkiG9w0BAQsFADBn\r\n"
				+ "MSswKQYDVQQLDCJDcmVhdGVkIGJ5IGh0dHA6Ly93d3cuZmlkZGxlcjIuY29tMRUw\r\n"
				+ "EwYDVQQKDAxET19OT1RfVFJVU1QxITAfBgNVBAMMGERPX05PVF9UUlVTVF9GaWRk\r\n"
				+ "bGVyUm9vdDAeFw0xNzA5MjAxMTQ2NDFaFw0yMzA5MjAxMTQ2NDFaMGcxKzApBgNV\r\n"
				+ "BAsMIkNyZWF0ZWQgYnkgaHR0cDovL3d3dy5maWRkbGVyMi5jb20xFTATBgNVBAoM\r\n"
				+ "DERPX05PVF9UUlVTVDEhMB8GA1UEAwwYRE9fTk9UX1RSVVNUX0ZpZGRsZXJSb290\r\n"
				+ "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArsx4Ks3DllC/P5ZMbr5d\r\n"
				+ "fy+N0jooTAbqvg1p4ny3SYmyR1IWn62YSb/bcXEClggfyjrUNd+BbJqV2P50+YXX\r\n"
				+ "FdzkvJcfwNXX38QTVG3jt3pXmSAj6Mok8QGkN95YoKWUDOTKYEYBFiamXg7Ilwn5\r\n"
				+ "pizGScybalQnUXG4Gas1aw2Ep01Z5U3txDthunp4n7wsDJLAgVVQ7UEDehwCkc/c\r\n"
				+ "yZ3Jo1oGPV4hTHjQaia7RrAzbtVHTzZb7/CuyyBxkoEhVG9T573vRj5H7IwI8pAi\r\n"
				+ "qaG1Jxv2H0G26pbv+3asGDoFrCG3sy8dlSDvENk6DNrSYEWJj7MUB7PZe9jwfbWL\r\n"
				+ "tQIDAQABo1owWDATBgNVHSUEDDAKBggrBgEFBQcDATASBgNVHRMBAf8ECDAGAQH/\r\n"
				+ "AgEAMB0GA1UdDgQWBBS2UcdwKCk+RaZ3pDLchT4LvcgHGjAOBgNVHQ8BAf8EBAMC\r\n"
				+ "AQYwDQYJKoZIhvcNAQELBQADggEBAKgHso1kM27hD7ybHsGZFC17fq2axuEWMTSG\r\n"
				+ "1+Q7zUhbxGCXJBP6twWjo0CD5DDYgfCzorHIYG1zZQ+3dPXC6lkuD7/yYaC1ntSO\r\n"
				+ "mRJ6X8JQgcSEtfmJtVAf7WaZF6epI/Kx+DTbd3XTaD62YDfsAFfsd8uVt62XnRfK\r\n"
				+ "cFijE/S7cZRH4bpERTozKiS8o9C9of8rEKfYQHZl/UyaLjsSJyl2giVCtFCu2iB9\r\n"
				+ "oQ4en2dfehEr4eE98L9wgXtIbjjRoiDSGY25nVNJAcl4oBS7DskatSohQZ08EJ1V\r\n"
				+ "FSpKdbe2HRI1bzLQIZ/eNW/BUWtVKZB/ETxSnJyFg5ahbN2Clzo=\r\n" + "-----END CERTIFICATE-----\n";

		return new Buffer().writeUtf8(fiddlerCertificationAuthority).inputStream();
	}

	private static X509TrustManager trustManagerForCertificates(InputStream in) throws GeneralSecurityException
	{
		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
		Collection<? extends Certificate> certificates = certificateFactory.generateCertificates(in);
		if (certificates.isEmpty())
		{
			throw new IllegalArgumentException("expected non-empty set of trusted certificates");
		}

		// Put the certificates a key store.
		char[] password = "password".toCharArray();
		// Any password will work.
		KeyStore keyStore = newEmptyKeyStore(password);
		int index = 0;
		for (Certificate certificate : certificates)
		{
			String certificateAlias = Integer.toString(index++);
			keyStore.setCertificateEntry(certificateAlias, certificate);
		}

		// Use it to build an X509 trust manager.
		KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
		keyManagerFactory.init(keyStore, password);
		TrustManagerFactory trustManagerFactory = TrustManagerFactory
				.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		trustManagerFactory.init(keyStore);
		TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
		if (trustManagers.length != 1 || !(trustManagers[0] instanceof X509TrustManager))
		{
			throw new IllegalStateException("Unexpected default trust managers:" + Arrays.toString(trustManagers));
		}
		return (X509TrustManager) trustManagers[0];
	}

	private static KeyStore newEmptyKeyStore(char[] password) throws GeneralSecurityException
	{
		try
		{
			KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
			InputStream in = null;
			// By convention, 'null' creates an empty key store.
			keyStore.load(in, password);
			return keyStore;
		}
		catch (IOException e)
		{
			throw new AssertionError(e);
		}
	}
	 
}
