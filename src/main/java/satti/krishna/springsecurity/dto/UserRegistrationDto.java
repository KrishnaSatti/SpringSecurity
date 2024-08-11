package satti.krishna.springsecurity.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;

/**
 * @author atquil
 */
public record UserRegistrationDto (
        @NotEmpty(message = "User Name must not be empty")
        String userName,
        String userMobileNo,
        @NotEmpty(message = "User email must not be empty")
        @Email(message = "Invalid email format")
        String userEmail,
        @NotEmpty(message = "User password must not be empty")
        String userPassword,
        @NotEmpty(message = "User role must not be empty")
        String userRole
) {
    public static UserRegistrationDto fromGoogleSignIn(String email) {
        return new UserRegistrationDto(
            email.split("@")[0], // Set the username as the part before '@' in the email
            null,                // Mobile number is not provided, so it's set to null
            email,
            "googleUser",        // Default password or unique identifier for Google users
            "ROLE_USER"          // Default role for a new user
        );
    }
}

