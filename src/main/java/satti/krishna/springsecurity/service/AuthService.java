package satti.krishna.springsecurity.service;

import satti.krishna.springsecurity.config.jwtAuth.JwtTokenGenerator;
import satti.krishna.springsecurity.dto.AuthResponseDto;
import satti.krishna.springsecurity.dto.TokenType;
import satti.krishna.springsecurity.dto.UserRegistrationDto;
import satti.krishna.springsecurity.entity.RefreshTokenEntity;
import satti.krishna.springsecurity.entity.UserInfoEntity;
import satti.krishna.springsecurity.mapper.UserInfoMapper;
import satti.krishna.springsecurity.repo.RefreshTokenRepo;
import satti.krishna.springsecurity.repo.UserInfoRepo;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.Arrays;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final UserInfoRepo userInfoRepo;
    private final JwtTokenGenerator jwtTokenGenerator;
    private final RefreshTokenRepo refreshTokenRepo;
    private final UserInfoMapper userInfoMapper;

    public AuthResponseDto getJwtTokensAfterAuthentication(Authentication authentication, HttpServletResponse response) {
        try {
            log.info("[AuthService:getJwtTokensAfterAuthentication] Authenticating user: {}", authentication.getName());
            var userInfoEntity = userInfoRepo.findByEmailId(authentication.getName())
                    .orElseThrow(() -> {
                        log.error("[AuthService:getJwtTokensAfterAuthentication] User {} not found", authentication.getName());
                        return new ResponseStatusException(HttpStatus.NOT_FOUND, "USER NOT FOUND ");
                    });

            String accessToken = jwtTokenGenerator.generateAccessToken(authentication);
            String refreshToken = jwtTokenGenerator.generateRefreshToken(authentication);

            log.info("[AuthService:getJwtTokensAfterAuthentication] Saving refresh token for user: {}", userInfoEntity.getUserName());
            saveUserRefreshToken(userInfoEntity, refreshToken);

            log.info("[AuthService:getJwtTokensAfterAuthentication] Creating refresh token cookie for user: {}", userInfoEntity.getUserName());
            createRefreshTokenCookie(response, refreshToken);

            log.info("[AuthService:getJwtTokensAfterAuthentication] Access token generated for user: {}", userInfoEntity.getUserName());
            return AuthResponseDto.builder()
                    .accessToken(accessToken)
                    .accessTokenExpiry(15 * 60)
                    .userName(userInfoEntity.getUserName())
                    .tokenType(TokenType.Bearer)
                    .build();

        } catch (Exception e) {
            log.error("[AuthService:getJwtTokensAfterAuthentication] Exception while authenticating the user: {}", e.getMessage());
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Please Try Again");
        }
    }

    public AuthResponseDto getAccessTokenUsingRefreshToken(String refreshToken) {
        log.info("[AuthService:getAccessTokenUsingRefreshToken] Processing refresh token");

        // Find refresh token from database and validate
        var refreshTokenEntity = refreshTokenRepo.findByRefreshToken(refreshToken)
                .filter(tokens -> !tokens.isRevoked())
                .orElseThrow(() -> {
                    log.error("[AuthService:getAccessTokenUsingRefreshToken] Refresh token is revoked or invalid");
                    return new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Refresh token revoked");
                });

        UserInfoEntity userInfoEntity = refreshTokenEntity.getUser();
        log.info("[AuthService:getAccessTokenUsingRefreshToken] Refresh token is valid for user: {}", userInfoEntity.getUserName());

        // Create the Authentication object
        Authentication authentication = createAuthenticationObject(userInfoEntity);

        // Generate new access token
        String accessToken = jwtTokenGenerator.generateAccessToken(authentication);
        log.info("[AuthService:getAccessTokenUsingRefreshToken] Access token generated for user: {}", userInfoEntity.getUserName());

        return AuthResponseDto.builder()
                .accessToken(accessToken)
                .accessTokenExpiry(5 * 60)
                .userName(userInfoEntity.getUserName())
                .tokenType(TokenType.Bearer)
                .build();
    }

    private void saveUserRefreshToken(UserInfoEntity userInfoEntity, String refreshToken) {
        log.info("[AuthService:saveUserRefreshToken] Saving refresh token for user: {}", userInfoEntity.getUserName());
        var refreshTokenEntity = RefreshTokenEntity.builder()
                .user(userInfoEntity)
                .refreshToken(refreshToken)
                .revoked(false)
                .build();
        refreshTokenRepo.save(refreshTokenEntity);
    }

    private Cookie createRefreshTokenCookie(HttpServletResponse response, String refreshToken) {
        log.info("[AuthService:createRefreshTokenCookie] Creating refresh token cookie");
        Cookie refreshTokenCookie = new Cookie("refresh_token", refreshToken);
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setSecure(true);
        refreshTokenCookie.setMaxAge(15 * 24 * 60 * 60); // in seconds
        response.addCookie(refreshTokenCookie);
        return refreshTokenCookie;
    }

    public AuthResponseDto registerUser(UserRegistrationDto userRegistrationDto,
                                        HttpServletResponse httpServletResponse) {
        try {
            log.info("[AuthService:registerUser] User registration started for: {}", userRegistrationDto.userName());

            Optional<UserInfoEntity> user = userInfoRepo.findByEmailId(userRegistrationDto.userEmail());
            if (user.isPresent()) {
                log.warn("[AuthService:registerUser] User {} already exists", userRegistrationDto.userEmail());
                throw new Exception("User Already Exists");
            }

            UserInfoEntity userDetailsEntity = userInfoMapper.convertToEntity(userRegistrationDto);
            Authentication authentication = createAuthenticationObject(userDetailsEntity);

            String accessToken = jwtTokenGenerator.generateAccessToken(authentication);
            String refreshToken = jwtTokenGenerator.generateRefreshToken(authentication);

            log.info("[AuthService:registerUser] Saving user details for: {}", userRegistrationDto.userName());
            UserInfoEntity savedUserDetails = userInfoRepo.save(userDetailsEntity);

            log.info("[AuthService:registerUser] Saving refresh token for user: {}", savedUserDetails.getUserName());
            saveUserRefreshToken(savedUserDetails, refreshToken);

            log.info("[AuthService:registerUser] Creating refresh token cookie for user: {}", savedUserDetails.getUserName());
            createRefreshTokenCookie(httpServletResponse, refreshToken);

            log.info("[AuthService:registerUser] User {} successfully registered", savedUserDetails.getUserName());
            return AuthResponseDto.builder()
                    .accessToken(accessToken)
                    .accessTokenExpiry(5 * 60)
                    .userName(savedUserDetails.getUserName())
                    .tokenType(TokenType.Bearer)
                    .build();

        } catch (Exception e) {
            log.error("[AuthService:registerUser] Exception while registering the user: {}", e.getMessage());
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage());
        }
    }

    private static Authentication createAuthenticationObject(UserInfoEntity userInfoEntity) {
        String username = userInfoEntity.getEmailId();
        String password = userInfoEntity.getPassword();
        String roles = userInfoEntity.getRoles();

        log.info("[AuthService:createAuthenticationObject] Creating authentication object for user: {}", username);

        String[] roleArray = roles.split(",");
        GrantedAuthority[] authorities = Arrays.stream(roleArray)
                .map(role -> (GrantedAuthority) role::trim)
                .toArray(GrantedAuthority[]::new);

        return new UsernamePasswordAuthenticationToken(username, password, Arrays.asList(authorities));
    }
}
