package no.steras.opensamlSamples.opensaml4WebprofileDemo.idp;

import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.xml.security.utils.EncryptionConstants;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.schema.impl.XSStringBuilder;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.decoder.MessageDecodingException;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.saml.saml2.binding.decoding.impl.HTTPSOAP11Decoder;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPSOAP11Encoder;
import org.opensaml.saml.saml2.core.ArtifactResolve;
import org.opensaml.saml.saml2.core.ArtifactResponse;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.AttributeValue;
import org.opensaml.saml.saml2.core.Audience;
import org.opensaml.saml.saml2.core.AudienceRestriction;
import org.opensaml.saml.saml2.core.AuthnContext;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml.saml2.encryption.Encrypter;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.saml.saml2.core.impl.ArtifactResponseBuilder;
import org.opensaml.xmlsec.encryption.support.DataEncryptionParameters;
import org.opensaml.xmlsec.encryption.support.EncryptionException;
import org.opensaml.xmlsec.encryption.support.KeyEncryptionParameters;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.opensaml.xmlsec.signature.support.Signer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import no.steras.opensamlSamples.opensaml4WebprofileDemo.OpenSAMLUtils;
import no.steras.opensamlSamples.opensaml4WebprofileDemo.sp.SPConstants;

public class ArtifactResolutionServlet extends HttpServlet {
	private static Logger logger = LoggerFactory.getLogger(ArtifactResolutionServlet.class);
	private static String username, requestId, artifactId;

	@Override
	protected void doPost(final HttpServletRequest req, final HttpServletResponse resp)
			throws ServletException, IOException {
		HTTPSOAP11Decoder decoder = new HTTPSOAP11Decoder();
		decoder.setHttpServletRequest(req);

		try {
			decoder.initialize();
			decoder.decode();
		} catch (MessageDecodingException e) {
			throw new RuntimeException(e);
		} catch (ComponentInitializationException e) {
			throw new RuntimeException(e);
		}

		MessageContext messageContext = decoder.getMessageContext();
		ArtifactResolve artifactResolve = (ArtifactResolve) messageContext.getMessage();
		verifyArtifactResolveSignature(artifactResolve);

		logger.info("Recieved ArtifactResolve:");
		OpenSAMLUtils.logSAMLObject(artifactResolve);
		artifactId = artifactResolve.getID();

		ArtifactResponse artifactResponse = buildArtifactResponse();
		MessageContext context = new MessageContext();
		context.setMessage(artifactResponse);

		HTTPSOAP11Encoder encoder = new HTTPSOAP11Encoder();
		encoder.setMessageContext(context);
		encoder.setHttpServletResponse(resp);
		try {
			encoder.prepareContext();
			encoder.initialize();
			encoder.encode();
		} catch (MessageEncodingException e) {
			throw new RuntimeException(e);
		} catch (ComponentInitializationException e) {
			throw new RuntimeException(e);
		}
		logger.info("Sent ArtifactResponse");
	}

	private void verifyArtifactResolveSignature(ArtifactResolve artifactResolve) {

		if (!artifactResolve.isSigned()) {
			throw new RuntimeException("The SAML ArtifactResolve was not signed");
		}
		try {
			SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
			profileValidator.validate(artifactResolve.getSignature());
			SignatureValidator.validate(artifactResolve.getSignature(), IDPCredentials.getSPublicKeyCredential());

			logger.info("SAML ArtifactResolve signature verified");
		} catch (SignatureException e) {
			throw new RuntimeException("The SAML ArtifactResolve Signature is invalid");
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private ArtifactResponse buildArtifactResponse() {

		ArtifactResponseBuilder artifactResponseBuilder = new ArtifactResponseBuilder();
		ArtifactResponse artifactResponse = artifactResponseBuilder.buildObject();

		Issuer issuer = OpenSAMLUtils.buildSAMLObject(Issuer.class);
		issuer.setValue(IDPConstants.IDP_ENTITY_ID);
		artifactResponse.setIssuer(issuer);
		artifactResponse.setIssueInstant(Instant.now());
		artifactResponse.setDestination(SPConstants.ASSERTION_CONSUMER_SERVICE);
		artifactResponse.setID(OpenSAMLUtils.generateSecureRandomId());
		artifactResponse.setInResponseTo(artifactId);

		Status status = OpenSAMLUtils.buildSAMLObject(Status.class);
		StatusCode statusCode = OpenSAMLUtils.buildSAMLObject(StatusCode.class);
		statusCode.setValue(StatusCode.SUCCESS);
		status.setStatusCode(statusCode);
		artifactResponse.setStatus(status);

		Response response = OpenSAMLUtils.buildSAMLObject(Response.class);
		response.setDestination(SPConstants.ASSERTION_CONSUMER_SERVICE);
		response.setIssueInstant(Instant.now());
		response.setID(OpenSAMLUtils.generateSecureRandomId());
		response.setInResponseTo(requestId);
		Issuer issuer2 = OpenSAMLUtils.buildSAMLObject(Issuer.class);
		issuer.setValue(IDPConstants.IDP_ENTITY_ID);
		response.setIssuer(issuer2);
		artifactResponse.setMessage(response);

		Assertion assertion = buildAssertion();
		signAssertion(assertion);
		EncryptedAssertion encryptedAssertion = null;
		try {
			encryptedAssertion = encryptAssertion(assertion);
		} catch (Exception e) {
			e.printStackTrace();
		}
		response.getEncryptedAssertions().add(encryptedAssertion);

		return artifactResponse;
	}

	private EncryptedAssertion encryptAssertion(Assertion assertion) throws Exception {
		DataEncryptionParameters encryptionParameters = new DataEncryptionParameters();

		KeyEncryptionParameters keyEncryptionParameters = new KeyEncryptionParameters();
		keyEncryptionParameters.setEncryptionCredential(IDPCredentials.getSPublicKeyCredential());
		keyEncryptionParameters.setAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP);

		Encrypter encrypter = new Encrypter(encryptionParameters, keyEncryptionParameters);
		encrypter.setKeyPlacement(Encrypter.KeyPlacement.INLINE);

		try {
			EncryptedAssertion encryptedAssertion = encrypter.encrypt(assertion);
			OpenSAMLUtils.logSAMLObject(encryptedAssertion);
			return encryptedAssertion;
		} catch (EncryptionException e) {
			throw new RuntimeException(e);
		}
	}

	private void signAssertion(Assertion assertion) {
		Signature signature = OpenSAMLUtils.buildSAMLObject(Signature.class);
		signature.setSigningCredential(IDPCredentials.getCredential());
		signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
		signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

		assertion.setSignature(signature);
		try {
			XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(assertion).marshall(assertion);
			Signer.signObject(signature);
		} catch (SignatureException e) {
			throw new RuntimeException(e);
		} catch (MarshallingException e) {
			throw new RuntimeException(e);
		}
	}

	private Assertion buildAssertion() {

		Assertion assertion = OpenSAMLUtils.buildSAMLObject(Assertion.class);

		Issuer issuer = OpenSAMLUtils.buildSAMLObject(Issuer.class);
		issuer.setValue(IDPConstants.IDP_ENTITY_ID);
		assertion.setIssuer(issuer);
		assertion.setIssueInstant(Instant.now());

		assertion.setID(OpenSAMLUtils.generateSecureRandomId());

		Subject subject = OpenSAMLUtils.buildSAMLObject(Subject.class);
		assertion.setSubject(subject);

		NameID nameID = OpenSAMLUtils.buildSAMLObject(NameID.class);
		nameID.setFormat(NameIDType.TRANSIENT);
		nameID.setSPNameQualifier("http://localhost:7070/Idp/artifactResolutionService");
		nameID.setNameQualifier("");

		subject.setNameID(nameID);
		subject.getSubjectConfirmations().add(buildSubjectConfirmation());
		assertion.setConditions(buildConditions());
		assertion.getAttributeStatements().add(buildAttributeStatement());
		assertion.getAuthnStatements().add(buildAuthnStatement());

		return assertion;
	}

	private SubjectConfirmation buildSubjectConfirmation() {
		SubjectConfirmation subjectConfirmation = OpenSAMLUtils.buildSAMLObject(SubjectConfirmation.class);
		subjectConfirmation.setMethod(SubjectConfirmation.METHOD_BEARER);

		SubjectConfirmationData subjectConfirmationData = OpenSAMLUtils.buildSAMLObject(SubjectConfirmationData.class);
		subjectConfirmationData.setNotBefore(Instant.now());
		subjectConfirmationData.setNotOnOrAfter(Instant.now().plus(10, ChronoUnit.MINUTES));
		subjectConfirmationData.setRecipient(SPConstants.ASSERTION_CONSUMER_SERVICE);

		subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);

		return subjectConfirmation;
	}

	private AuthnStatement buildAuthnStatement() {
		AuthnStatement authnStatement = OpenSAMLUtils.buildSAMLObject(AuthnStatement.class);
		AuthnContext authnContext = OpenSAMLUtils.buildSAMLObject(AuthnContext.class);
		AuthnContextClassRef authnContextClassRef = OpenSAMLUtils.buildSAMLObject(AuthnContextClassRef.class);
		authnContextClassRef.setURI(AuthnContext.PASSWORD_AUTHN_CTX);
		authnContext.setAuthnContextClassRef(authnContextClassRef);
		authnStatement.setAuthnContext(authnContext);
		authnStatement.setAuthnInstant(Instant.now());

		return authnStatement;
	}

	private Conditions buildConditions() {
		Conditions conditions = OpenSAMLUtils.buildSAMLObject(Conditions.class);
		conditions.setNotBefore(Instant.now());
		conditions.setNotOnOrAfter(Instant.now().plus(10, ChronoUnit.MINUTES));
		AudienceRestriction audienceRestriction = OpenSAMLUtils.buildSAMLObject(AudienceRestriction.class);
		Audience audience = OpenSAMLUtils.buildSAMLObject(Audience.class);
		audience.setURI(SPConstants.ASSERTION_CONSUMER_SERVICE);
		audienceRestriction.getAudiences().add(audience);
		conditions.getAudienceRestrictions().add(audienceRestriction);
		return conditions;
	}

	private AttributeStatement buildAttributeStatement() {
		AttributeStatement attributeStatement = OpenSAMLUtils.buildSAMLObject(AttributeStatement.class);

		Attribute attributeUserName = OpenSAMLUtils.buildSAMLObject(Attribute.class);

		XSStringBuilder stringBuilder = (XSStringBuilder) XMLObjectProviderRegistrySupport.getBuilderFactory()
				.getBuilder(XSString.TYPE_NAME);
		XSString userNameValue = stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
		userNameValue.setValue(username);

		attributeStatement.getAttributes().add(attributeUserName);
		attributeUserName.getAttributeValues().add(userNameValue);
		attributeUserName.setName("username");

		return attributeStatement;
	}

	public static void setUser(String user) {
		ArtifactResolutionServlet.username = user;
	}

	public static void setUsersetRequestId(String reqId) {
		ArtifactResolutionServlet.requestId = reqId;
	}
}
