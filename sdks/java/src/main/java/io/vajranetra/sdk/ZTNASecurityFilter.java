package io.vajranetra.sdk;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class ZTNASecurityFilter implements Filter {
    public static final String ZTNA_CONTEXT_KEY = "VAJRANETRA_ZTNA_CONTEXT";
    private ZTNASignatureVerifier verifier;
    private boolean enforce = true;

    @Override
    public void init(FilterConfig filterConfig) {
        String secretKey = filterConfig.getInitParameter("secretKey");
        if (secretKey == null || secretKey.isEmpty()) {
            secretKey = System.getenv("VAJRANETRA_SECRET_KEY");
        }
        String enforceParam = filterConfig.getInitParameter("enforce");
        if (enforceParam != null) {
            this.enforce = Boolean.parseBoolean(enforceParam);
        }
        this.verifier = new ZTNASignatureVerifier(secretKey != null ? secretKey : "default-secret");
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        Map<String, String> headers = new HashMap<>();
        for (String headerName : Collections.list(httpRequest.getHeaderNames())) {
            headers.put(headerName.toLowerCase(), httpRequest.getHeader(headerName));
        }

        try {
            ZTNAContext ctx = verifier.verifyHeaders(headers);
            httpRequest.setAttribute(ZTNA_CONTEXT_KEY, ctx);
            chain.doFilter(request, response);
        } catch (Exception ex) {
            if (enforce) {
                httpResponse.setStatus(HttpServletResponse.SC_FORBIDDEN);
                httpResponse.setContentType("application/json");
                httpResponse.getWriter().write("{\"error\":\"ztna_verification_failed\",\"detail\":\"" + ex.getMessage() + "\"}");
            } else {
                chain.doFilter(request, response);
            }
        }
    }
}
