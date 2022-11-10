package no.steras.opensamlSamples.opensaml4WebprofileDemo.sp;

import java.io.IOException;
import java.time.Instant;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.messaging.context.InOutOperationContext;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.messaging.pipeline.httpclient.BasicHttpClientMessagePipeline;
import org.opensaml.messaging.pipeline.httpclient.HttpClientMessagePipeline;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.common.binding.security.impl.SAMLOutboundProtocolMessageSigningHandler;
import org.opensaml.saml.saml2.binding.decoding.impl.HttpClientResponseSOAP11Decoder;
import org.opensaml.saml.saml2.binding.encoding.impl.HttpClientRequestSOAP11Encoder;
import org.opensaml.saml.saml2.core.Artifact;
import org.opensaml.saml.saml2.core.ArtifactResolve;
import org.opensaml.saml.saml2.core.ArtifactResponse;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.encryption.Decrypter;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.soap.client.http.AbstractPipelineHttpSOAPClient;
import org.opensaml.soap.common.SOAPException;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.encryption.support.DecryptionException;
import org.opensaml.xmlsec.encryption.support.InlineEncryptedKeyResolver;
import org.opensaml.xmlsec.keyinfo.impl.StaticKeyInfoCredentialResolver;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.opensaml.xmlsec.signature.support.Signer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.httpclient.HttpClientBuilder;
import no.steras.opensamlSamples.opensaml4WebprofileDemo.OpenSAMLUtils;
import no.steras.opensamlSamples.opensaml4WebprofileDemo.idp.IDPConstants;

public class ConsumerServlet extends HttpServlet {
	private static Logger logger = LoggerFactory.getLogger(ConsumerServlet.class);
	private String username;

	@Override
	protected void doGet(final HttpServletRequest req, final HttpServletResponse resp)
			throws ServletException, IOException {
		logger.info("Artifact received");
		Artifact artifact = buildArtifactFromRequest(req);
		logger.info("Artifact: " + artifact.getArtifact());

		ArtifactResolve artifactResolve = buildArtifactResolve(artifact);
		logger.info("Sending ArtifactResolve");

		ArtifactResponse artifactResponse = sendAndReceiveArtifactResolve(artifactResolve);
		logger.info("ArtifactResponse received");
		logger.info("ArtifactResponse: ");
		OpenSAMLUtils.logSAMLObject(artifactResponse);

		EncryptedAssertion encryptedAssertion = getEncryptedAssertion(artifactResponse);
		Assertion assertion = decryptAssertion(encryptedAssertion);
		verifyAssertionSignature(assertion);
		logger.info("Decrypted Assertion: ");
		OpenSAMLUtils.logSAMLObject(assertion);

		logAssertionAttributes(assertion);
		username = getUsername(assertion);

		setAuthenticatedSession(req);
		redirectToGotoURL(req, resp);
	}

	private Assertion decryptAssertion(EncryptedAssertion encryptedAssertion) {
		StaticKeyInfoCredentialResolver keyInfoCredentialResolver = new StaticKeyInfoCredentialResolver(
				SPCredentials.getCredential());

		Decrypter decrypter = new Decrypter(null, keyInfoCredentialResolver, new InlineEncryptedKeyResolver());
		decrypter.setRootInNewDocument(true);

		try {
			return decrypter.decrypt(encryptedAssertion);
		} catch (DecryptionException e) {
			throw new RuntimeException(e);
		}
	}

	private void verifyAssertionSignature(Assertion assertion) {

		if (!assertion.isSigned()) {
			throw new RuntimeException("The SAML Assertion was not signed");
		}
		try {
			SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
			profileValidator.validate(assertion.getSignature());
			SignatureValidator.validate(assertion.getSignature(), SPCredentials.getIDPublicKeyCredential());

			logger.info("SAML Assertion signature verified");
		} catch (SignatureException e) {
			throw new RuntimeException("The SAML Assertion Signature is invalid");
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private void setAuthenticatedSession(HttpServletRequest req) {
		req.getSession().setAttribute(SPConstants.AUTHENTICATED_SESSION_ATTRIBUTE, true);
	}

	private void redirectToGotoURL(HttpServletRequest req, HttpServletResponse resp) {
		String gotoURL = (String) req.getSession().getAttribute(SPConstants.GOTO_URL_SESSION_ATTRIBUTE);
		logger.info("Redirecting to requested URL: " + gotoURL);
		req.getSession().setAttribute("user", username);
		try {
			resp.sendRedirect(gotoURL);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	private void logAssertionAttributes(Assertion assertion) {
		for (Attribute attribute : assertion.getAttributeStatements().get(0).getAttributes()) {
			logger.info("Attribute name: " + attribute.getName());
			for (XMLObject attributeValue : attribute.getAttributeValues()) {
				logger.info("Attribute value: " + ((XSString) attributeValue).getValue());
			}
		}
	}

	private String getUsername(Assertion assertion) {
		for (Attribute attribute : assertion.getAttributeStatements().get(0).getAttributes()) {
			logger.info("Attribute name: " + attribute.getName());
			if (attribute.getName().equalsIgnoreCase("username")) {
				return ((XSString) attribute.getAttributeValues().get(0)).getValue();
			}
		}
		return null;
	}

	private EncryptedAssertion getEncryptedAssertion(ArtifactResponse artifactResponse) {
		Response response = (Response) artifactResponse.getMessage();
		return response.getEncryptedAssertions().get(0);
	}

	private ArtifactResponse sendAndReceiveArtifactResolve(final ArtifactResolve artifactResolve) {
		try {
			MessageContext contextout = new MessageContext();
			contextout.setMessage(artifactResolve);

			Signature signature = OpenSAMLUtils.buildSAMLObject(Signature.class);
			signature.setSigningCredential(SPCredentials.getCredential());
			signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
			signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

			artifactResolve.setSignature(signature);
			try {
				XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(artifactResolve)
						.marshall(artifactResolve);
				Signer.signObject(signature);
			} catch (SignatureException e) {
				throw new RuntimeException(e);
			} catch (MarshallingException e) {
				throw new RuntimeException(e);
			}

			InOutOperationContext context = new ProfileRequestContext();
			context.setOutboundMessageContext(contextout);

			AbstractPipelineHttpSOAPClient soapClient = new AbstractPipelineHttpSOAPClient() {
				protected HttpClientMessagePipeline newPipeline() throws SOAPException {
					HttpClientRequestSOAP11Encoder encoder = new HttpClientRequestSOAP11Encoder();
					HttpClientResponseSOAP11Decoder decoder = new HttpClientResponseSOAP11Decoder();
					BasicHttpClientMessagePipeline pipeline = new BasicHttpClientMessagePipeline(encoder, decoder);

					pipeline.setOutboundPayloadHandler(new SAMLOutboundProtocolMessageSigningHandler());
					return pipeline;
				}
			};

			HttpClientBuilder clientBuilder = new HttpClientBuilder();

			soapClient.setHttpClient(clientBuilder.buildClient());
			soapClient.send(IDPConstants.ARTIFACT_RESOLUTION_SERVICE, context);

			return (ArtifactResponse) context.getInboundMessageContext().getMessage();
		} catch (SecurityException e) {
			throw new RuntimeException(e);
		} catch (ComponentInitializationException e) {
			throw new RuntimeException(e);
		} catch (MessageEncodingException e) {
			throw new RuntimeException(e);
		} catch (IllegalAccessException e) {
			throw new RuntimeException(e);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}

	}

	private Artifact buildArtifactFromRequest(final HttpServletRequest req) {
		Artifact artifact = OpenSAMLUtils.buildSAMLObject(Artifact.class);
		artifact.setValue(req.getParameter("SAMLart"));
		return artifact;
	}

	private ArtifactResolve buildArtifactResolve(final Artifact artifact) {

		ArtifactResolve artifactResolve = OpenSAMLUtils.buildSAMLObject(ArtifactResolve.class);
		Issuer issuer = OpenSAMLUtils.buildSAMLObject(Issuer.class);
		issuer.setValue(SPConstants.SP_ENTITY_ID);

		artifactResolve.setIssuer(issuer);
		artifactResolve.setIssueInstant(Instant.now());
		artifactResolve.setID(OpenSAMLUtils.generateSecureRandomId());
		artifactResolve.setDestination(IDPConstants.ARTIFACT_RESOLUTION_SERVICE);
		artifactResolve.setArtifact(artifact);

		return artifactResolve;
	}

}