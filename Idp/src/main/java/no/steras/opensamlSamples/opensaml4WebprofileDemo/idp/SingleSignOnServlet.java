package no.steras.opensamlSamples.opensaml4WebprofileDemo.idp;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import no.steras.opensamlSamples.opensaml4WebprofileDemo.sp.SPConstants;

import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.opensaml.saml.saml2.binding.decoding.impl.HTTPPostDecoder;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import javax.servlet.ServletException;
import java.io.IOException;
import java.io.Writer;

public class SingleSignOnServlet extends HttpServlet {
    private static Logger logger = LoggerFactory.getLogger(SingleSignOnServlet.class);
    private static Connection conn;

    static {
        try {
            InitializationService.initialize();
        } catch (InitializationException e) {
            throw new RuntimeException("Initialization failed");
        }
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

        if (req.getParameter("username") != null) {
            validate(req, resp);
            return;
        }

        logger.info("AuthnRequest recieved");
        HTTPPostDecoder decoder = new HTTPPostDecoder();
        decoder.setHttpServletRequest(req);

        AuthnRequest authnRequest;
        try {
            decoder.initialize();
            decoder.decode();
        } catch (Exception e) {
            System.out.println(e);
        }

        MessageContext messageContext = decoder.getMessageContext();
        authnRequest = (AuthnRequest) messageContext.getMessage();
        verifyAuthnRequestSignature(authnRequest);

        ArtifactResolutionServlet.setUsersetRequestId(authnRequest.getID());

        Writer w = resp.getWriter();
        resp.setContentType("text/html");
        w.append("<html>"
                + "<head><title>User Panel</title><link rel=\"stylesheet\" href=\"https://maxcdn.bootstrapcdn.com/bootstrap/3.4.1/css/bootstrap.min.css\"></head>"
                + "<body style=\"overflow: hidden;\"><div class=\"container\" style=\"position: absolute; left: 36%; top: 25%\">"
                +
                "<h1 style=\"margin-left: 9%;\">Login Form</h1>" +
                "<form autocomplete=\"off\" method=\"post\" style=\"display: flex; flex-direction: column; justify-content: center; margin-top: 4%;\">"
                +
                "<label style=\"margin-left: 9%; margin-bottom: 2%;\">Login with your credentials</label>" +
                "<div class=\"form-group col-xs-4\">" +
                "<input class=\"form-control\" name=\"username\" required=\"required\" placeholder=\"Enter your Username\" style=\"margin-bottom: 4%; margin-left: 15%; width: 70%;\">"
                +
                "<input class=\"form-control\" name=\"password\" type=\"password\" required=\"required\" placeholder=\"Enter your Password\" style=\"width: 70%; margin-left: 15%;\">"
                +
                "</div>" +
                "<button type=\"submit\" class=\"btn btn-primary col-xs-2\" style=\"margin-top: 2%; margin-left: 10.5%; width: 12%;\">Submit</button>"
                +
                "</form>" +
                "</div>" +
                "</body> </html>");
        w.close();
    }

    private static void verifyAuthnRequestSignature(AuthnRequest authnRequest) {
        if (!authnRequest.isSigned()) {
            throw new RuntimeException("The SAML AuthnRequest was not signed");
        }
        try {
            Credential credential = IDPCredentials.getSPublicKeyCredential();
            SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
            profileValidator.validate(authnRequest.getSignature());
            SignatureValidator.validate(authnRequest.getSignature(),
                    credential);
            logger.info("Authnrequest signature verified");
        } catch (SignatureException e) {
            e.printStackTrace();
            throw new RuntimeException("The SAML AuthnRequest Signature is invalid");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void validate(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String username = req.getParameter("username"), password = req.getParameter("password");
        try {
            Class.forName("com.mysql.jdbc.Driver");
            conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/saml", "sri", "Sri@1104");
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE username = '" + username + "'");
            if (rs.next() && rs.getString("password").equals(password)) {
                ArtifactResolutionServlet.setUser(username);
            } else {
                throw new RuntimeException("Invalid username or password");
            }
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } catch (SQLException e) {
            e.printStackTrace();
        }

        resp.sendRedirect(SPConstants.ASSERTION_CONSUMER_SERVICE +
                "?SAMLart=AAQAAMFbLinlXaCM%2BFIxiDwGOLAy2T71gbpO7ZhNzAgEANlB90ECfpNEVLg%3D");
    }
}