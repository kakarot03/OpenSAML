package no.steras.opensamlSamples.opensaml4WebprofileDemo.app;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class ApplicationServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        resp.setContentType("text/html");
        resp.getWriter().append(
                "<h1>Hi " + req.getSession().getAttribute("user") + ", You are now at the requested resource</h1>");
    }
}
