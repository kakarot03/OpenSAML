package org.apache.jsp;

import javax.servlet.*;
import javax.servlet.http.*;
import javax.servlet.jsp.*;

public final class Login_jsp extends org.apache.jasper.runtime.HttpJspBase
    implements org.apache.jasper.runtime.JspSourceDependent {

  private static final JspFactory _jspxFactory = JspFactory.getDefaultFactory();

  private static java.util.List _jspx_dependants;

  private javax.el.ExpressionFactory _el_expressionfactory;
  private org.apache.AnnotationProcessor _jsp_annotationprocessor;

  public Object getDependants() {
    return _jspx_dependants;
  }

  public void _jspInit() {
    _el_expressionfactory = _jspxFactory.getJspApplicationContext(getServletConfig().getServletContext()).getExpressionFactory();
    _jsp_annotationprocessor = (org.apache.AnnotationProcessor) getServletConfig().getServletContext().getAttribute(org.apache.AnnotationProcessor.class.getName());
  }

  public void _jspDestroy() {
  }

  public void _jspService(HttpServletRequest request, HttpServletResponse response)
        throws java.io.IOException, ServletException {

    PageContext pageContext = null;
    HttpSession session = null;
    ServletContext application = null;
    ServletConfig config = null;
    JspWriter out = null;
    Object page = this;
    JspWriter _jspx_out = null;
    PageContext _jspx_page_context = null;


    try {
      response.setContentType("text/html");
      pageContext = _jspxFactory.getPageContext(this, request, response,
      			null, true, 8192, true);
      _jspx_page_context = pageContext;
      application = pageContext.getServletContext();
      config = pageContext.getServletConfig();
      session = pageContext.getSession();
      out = pageContext.getOut();
      _jspx_out = out;

      out.write("<!DOCTYPE html>\r\n");
      out.write("<html>\r\n");
      out.write("\r\n");
      out.write("<head>\r\n");
      out.write("    <title>Login Form</title>\r\n");
      out.write("    <link rel=\"stylesheet\" href=\"https://maxcdn.bootstrapcdn.com/bootstrap/3.4.1/css/bootstrap.min.css\">\r\n");
      out.write("</head>\r\n");
      out.write("\r\n");
      out.write("<body style=\"overflow: hidden;\">\r\n");
      out.write("    <div class=\"container\" style=\"position: absolute; left: 36%; top: 25%\">\r\n");
      out.write("        <h1 style=\"margin-left: 9%;\">Login Form</h1>\r\n");
      out.write("        <form action='j_security_check' autocomplete=\"off\" method=\"post\"\r\n");
      out.write("            style=\"display: flex; flex-direction: column; justify-content: center; margin-top: 4%;\">\r\n");
      out.write("            <label style=\"margin-left: 9%; margin-bottom: 2%;\">Login with your credentials</label>\r\n");
      out.write("            <div class=\"form-group col-xs-4\">\r\n");
      out.write("                <input class=\"form-control\" id=\"username\" name=\"username\" required=\"required\"\r\n");
      out.write("                    placeholder=\"Enter your Username\" style=\"margin-bottom: 4%; margin-left: 15%; width: 70%;\">\r\n");
      out.write("                <input class=\"form-control\" id=\"password\" name=\"password\" type=\"password\" required=\"required\"\r\n");
      out.write("                    placeholder=\"Enter your Password\" style=\" width: 70%; margin-left: 15%;\">\r\n");
      out.write("            </div>\r\n");
      out.write("            <button type=\"submit\" class=\"btn btn-primary col-xs-2\"\r\n");
      out.write("                style=\"margin-top: 2%; margin-left: 10.5%; width: 12%;\">Login</button>\r\n");
      out.write("        </form>\r\n");
      out.write("    </div>\r\n");
      out.write("</body>\r\n");
      out.write("\r\n");
      out.write("</html>");
    } catch (Throwable t) {
      if (!(t instanceof SkipPageException)){
        out = _jspx_out;
        if (out != null && out.getBufferSize() != 0)
          try { out.clearBuffer(); } catch (java.io.IOException e) {}
        if (_jspx_page_context != null) _jspx_page_context.handlePageException(t);
      }
    } finally {
      _jspxFactory.releasePageContext(_jspx_page_context);
    }
  }
}
