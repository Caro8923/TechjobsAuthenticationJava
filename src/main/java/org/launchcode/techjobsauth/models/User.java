package org.launchcode.techjobsauth.models;

import jakarta.persistence.Entity;
import jakarta.validation.constraints.NotNull;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Entity
public class User extends AbstractEntity {

    @NotNull
    private String username;

    @NotNull
    private String pwHash;

    //BCryptPassword encoder variable
    private static final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

    public User() {}

    //constructor encodes password field
    public User(String username, String password) {
        this.username = username;
        this.pwHash = encoder.encode(password);
    }

    public String getUsername() {
        return username;
    }

    //method checks password values
    public boolean isMatchingPassword(String password) {
        return encoder.matches(password, pwHash);
    }
}
