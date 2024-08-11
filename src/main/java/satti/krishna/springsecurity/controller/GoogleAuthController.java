package satti.krishna.springsecurity.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import satti.krishna.springsecurity.config.user.UserInfoManagerConfig;
import satti.krishna.springsecurity.dto.UserRegistrationDto;
import satti.krishna.springsecurity.entity.UserInfoEntity;
import satti.krishna.springsecurity.repo.UserInfoRepo;
import satti.krishna.springsecurity.service.AuthService;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/google")
@RequiredArgsConstructor
@Slf4j
public class GoogleAuthController {

    private final UserInfoRepo userInfoRepo;
    private final AuthService authService;
    private final UserInfoManagerConfig userInfoManagerConfig;  // Inject your UserDetailsService

    @GetMapping("/login")
    public ResponseEntity<?> userInfo(@AuthenticationPrincipal OAuth2User principal, HttpServletResponse response) {
        String email = principal.getAttribute("email");
        log.info("[GoogleAuthController:userInfo] Google user email: {}", email);

        // Check if user already exists
        Optional<UserInfoEntity> userOptional = userInfoRepo.findByEmailId(email);
        UserInfoEntity user;
        if (userOptional.isEmpty()) {
            log.info("[GoogleAuthController:userInfo] User not found, creating a new account with email: {}", email);

            // Create a new user using the factory method
            UserRegistrationDto newUser = UserRegistrationDto.fromGoogleSignIn(email);
            authService.registerUser(newUser, response);

            // Fetch the newly created user
            user = userInfoRepo.findByEmailId(email).orElseThrow(() -> new RuntimeException("User not found after registration"));
        } else {
            user = userOptional.get();
        }

        // Load user details
        UserDetails userDetails = userInfoManagerConfig.loadUserByUsername(user.getEmailId());

        // Manually create the Authentication object
        Authentication authentication = new UsernamePasswordAuthenticationToken(
                userDetails, null, userDetails.getAuthorities());

        // Set the authentication in the security context
        // SecurityContextHolder.getContext().setAuthentication(authentication);

        log.info("[GoogleAuthController:userInfo] User authenticated, generating JWT tokens");

        // Generate JWT tokens
        return ResponseEntity.ok(authService.getJwtTokensAfterAuthentication(authentication, response));
    }
}

