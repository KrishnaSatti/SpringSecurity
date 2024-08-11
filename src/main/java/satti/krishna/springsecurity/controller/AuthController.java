package satti.krishna.springsecurity.controller;

import satti.krishna.springsecurity.dto.UserRegistrationDto;
import satti.krishna.springsecurity.service.AuthService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.support.DefaultMessageSourceResolvable;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthService authService;

    @PostMapping("/sign-in")
    public ResponseEntity<?> authenticateUser(Authentication authentication, HttpServletResponse response) {
        return ResponseEntity.ok(authService.getJwtTokensAfterAuthentication(authentication, response));
    }

    // @PreAuthorize("hasAuthority('SCOPE_REFRESH_TOKEN')")
    @PostMapping("/refresh-token")
    public ResponseEntity<?> getAccessToken(HttpServletRequest request) {
        log.info("[AuthController:getAccessToken] Starting refresh token process");

        String refreshToken = extractRefreshTokenFromCookie(request);
        if (refreshToken == null) {
            log.warn("[AuthController:getAccessToken] Refresh token is missing from cookies");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Refresh token is missing");
        }

        log.info("[AuthController:getAccessToken] Refresh token extracted successfully");
        return ResponseEntity.ok(authService.getAccessTokenUsingRefreshToken(refreshToken));
    }

    @PostMapping("/sign-up")
    public ResponseEntity<?> registerUser(@Valid @RequestBody UserRegistrationDto userRegistrationDto,
                                          BindingResult bindingResult, HttpServletResponse httpServletResponse) {

        log.info("[AuthController:registerUser] Signup process started for user: {}", userRegistrationDto.userName());
        if (bindingResult.hasErrors()) {
            List<String> errorMessage = bindingResult.getAllErrors().stream()
                    .map(DefaultMessageSourceResolvable::getDefaultMessage)
                    .toList();
            log.error("[AuthController:registerUser] Errors in user registration: {}", errorMessage);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorMessage);
        }
        log.info("[AuthController:registerUser] Registering user: {}", userRegistrationDto.userName());
        return ResponseEntity.ok(authService.registerUser(userRegistrationDto, httpServletResponse));
    }

    private String extractRefreshTokenFromCookie(HttpServletRequest request) {
        log.info("[AuthController:extractRefreshTokenFromCookie] Extracting refresh token from cookies");

        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("refresh_token".equals(cookie.getName())) {
                    log.info("[AuthController:extractRefreshTokenFromCookie] Refresh token found in cookies");
                    return cookie.getValue();
                }
            }
        }

        log.warn("[AuthController:extractRefreshTokenFromCookie] Refresh token not found in cookies");
        return null;
    }
}