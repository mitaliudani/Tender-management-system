package com.hit.security;

import java.io.IOException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/** Defense in depth for three legacy admin actions. Does not replace DAO-level authorization. */
@WebFilter(urlPatterns = {"/AcceptBidSrv", "/RejectBidSrv", "/RemoveNoticeSrv"})
public final class MutatingActionFilter implements Filter {
    @Override
    public void init(FilterConfig config) { }

    @Override
    public void doFilter(ServletRequest rawRequest, ServletResponse rawResponse, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) rawRequest;
        HttpServletResponse response = (HttpServletResponse) rawResponse;
        response.setHeader("Cache-Control", "no-store");

        if (!"POST".equals(request.getMethod())) {
            response.setHeader("Allow", "POST");
            response.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
            return;
        }

        HttpSession session = request.getSession(false);
        Object role = session == null ? null : session.getAttribute("user");
        Object username = session == null ? null : session.getAttribute("username");
        if (session == null
                || !(role instanceof String)
                || !"admin".equalsIgnoreCase((String) role)
                || !(username instanceof String)
                || ((String) username).trim().isEmpty()
                || !CsrfTokens.verify(session, request.getParameter("csrfToken"))) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN);
            return;
        }

        chain.doFilter(rawRequest, rawResponse);
    }

    @Override
    public void destroy() { }
}
