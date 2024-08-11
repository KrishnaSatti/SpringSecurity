package satti.krishna.springsecurity.config.jwtAuth;

import satti.krishna.springsecurity.config.RSAKeyRecord;
import satti.krishna.springsecurity.repo.RefreshTokenRepo;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;

@RequiredArgsConstructor
@Slf4j
public class JwtRefreshTokenFilter extends OncePerRequestFilter {

    private final RSAKeyRecord rsaKeyRecord;
    private final JwtTokenUtils jwtTokenUtils;
    private final RefreshTokenRepo refreshTokenRepo;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        try {
            log.info("[JwtRefreshTokenFilter:doFilterInternal] :: Started ");
            log.info("[JwtRefreshTokenFilter:doFilterInternal] Filtering the Http Request: {}", request.getRequestURI());

            // Extract refresh token from the cookie
            String token = null;
            Cookie[] cookies = request.getCookies();
            if (cookies != null) {
                for (Cookie cookie : cookies) {
                    log.debug("[JwtRefreshTokenFilter:doFilterInternal] Checking cookie: {}", cookie.getName());
                    if ("refresh_token".equals(cookie.getName())) {
                        token = cookie.getValue();
                        log.info("[JwtRefreshTokenFilter:doFilterInternal] Refresh token found in cookies");
                        break;
                    }
                }
            }

            if (token == null) {
                log.warn("[JwtRefreshTokenFilter:doFilterInternal] No refresh token found in cookies. Proceeding without setting authentication.");
                filterChain.doFilter(request, response);
                return;
            }

            log.info("[JwtRefreshTokenFilter:doFilterInternal] Decoding refresh token");
            JwtDecoder jwtDecoder = NimbusJwtDecoder.withPublicKey(rsaKeyRecord.rsaPublicKey()).build();
            final Jwt jwtRefreshToken = jwtDecoder.decode(token);

            log.info("[JwtRefreshTokenFilter:doFilterInternal] Extracting username from token");
            final String userName = jwtTokenUtils.getUserName(jwtRefreshToken);
            log.debug("[JwtRefreshTokenFilter:doFilterInternal] Username extracted: {}", userName);

            if (!userName.isEmpty() && SecurityContextHolder.getContext().getAuthentication() == null) {
                log.info("[JwtRefreshTokenFilter:doFilterInternal] No existing authentication found. Validating refresh token in database");

                // Check if refreshToken is present in the database and is valid
                var isRefreshTokenValidInDatabase = refreshTokenRepo.findByRefreshToken(jwtRefreshToken.getTokenValue())
                        .map(refreshTokenEntity -> {
                            log.debug("[JwtRefreshTokenFilter:doFilterInternal] Refresh token found in database. Revoked status: {}", refreshTokenEntity.isRevoked());
                            return !refreshTokenEntity.isRevoked();
                        })
                        .orElse(false);

                if (!isRefreshTokenValidInDatabase) {
                    log.warn("[JwtRefreshTokenFilter:doFilterInternal] Refresh token is invalid or revoked");
                } else {
                    log.info("[JwtRefreshTokenFilter:doFilterInternal] Refresh token is valid. Proceeding to authenticate user: {}", userName);

                    UserDetails userDetails = jwtTokenUtils.userDetails(userName);
                    if (jwtTokenUtils.isTokenValid(jwtRefreshToken, userDetails)) {
                        log.info("[JwtRefreshTokenFilter:doFilterInternal] JWT token is valid. Creating security context");

                        SecurityContext securityContext = SecurityContextHolder.createEmptyContext();

                        UsernamePasswordAuthenticationToken createdToken = new UsernamePasswordAuthenticationToken(
                                userDetails,
                                null,
                                userDetails.getAuthorities()
                        );

                        createdToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                        securityContext.setAuthentication(createdToken);
                        SecurityContextHolder.setContext(securityContext);

                        log.info("[JwtRefreshTokenFilter:doFilterInternal] Authentication successful for user: {}", userName);
                    } else {
                        log.warn("[JwtRefreshTokenFilter:doFilterInternal] JWT token validation failed for user: {}", userName);
                    }
                }
            } else if (userName.isEmpty()) {
                log.warn("[JwtRefreshTokenFilter:doFilterInternal] Username is empty in the JWT token");
            } else {
                log.info("[JwtRefreshTokenFilter:doFilterInternal] Security context already contains authentication. Skipping");
            }

            log.info("[JwtRefreshTokenFilter:doFilterInternal] Completed");
            filterChain.doFilter(request, response);
        } catch (JwtValidationException jwtValidationException) {
            log.error("[JwtRefreshTokenFilter:doFilterInternal] Exception during JWT validation: {}", jwtValidationException.getMessage());
            throw new ResponseStatusException(HttpStatus.NOT_ACCEPTABLE, jwtValidationException.getMessage());
        }
    }
}
