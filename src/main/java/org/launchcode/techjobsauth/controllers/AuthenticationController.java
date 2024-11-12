package org.launchcode.techjobsauth.controllers;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import org.launchcode.techjobsauth.models.User;
import org.launchcode.techjobsauth.models.dto.LoginFormDTO;
import org.launchcode.techjobsauth.models.dto.RegisterFormDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.launchcode.techjobsauth.models.data.UserRepository;
import org.springframework.ui.Model;
import org.springframework.validation.Errors;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

import java.util.Optional;

@Controller
public class AuthenticationController {

    @Autowired
    UserRepository userRepository;

    private static final String userSessionKey = "user";

    public User getUserFromSession(HttpSession session) {
        Integer userId = (Integer) session.getAttribute(userSessionKey);
        if (userId == null) {
            return null;
        }

        Optional<User> user = userRepository.findById(userId);

        if (user.isEmpty()) {
            return null;
        }

        return user.get();
    }

    private static void setUserInSession(HttpSession session, User user) {
        session.setAttribute(userSessionKey, user.getId());
    }

    //display registration form
    @GetMapping("/register")
    public String displayRegistrationForm(Model model) {
        model.addAttribute(new RegisterFormDTO());
        model.addAttribute("title", "Register");
        return "register";
    }

    //process registration form
    @PostMapping("/register")
    public String processRegistrationForm(@ModelAttribute @Valid RegisterFormDTO registerFormDTO,
                                          Errors errors, HttpServletRequest request,
                                          Model model) {

        //if validation errors, re-render registration
        if (errors.hasErrors()) {
            model.addAttribute("title", "Register");
            return "register";
        }

        //if username tied to a user, re-render form
        User existingUser = userRepository.findByUsername(registerFormDTO.getUsername());
        if (existingUser != null) {
            errors.rejectValue("username", "username.alreadyexists", "A user with that username already exists");
            model.addAttribute("title", "Register");
            return "register";
        }

        //if two form fields for password do not match, add error message and re-render the form
        String password = registerFormDTO.getPassword();
        String verifyPassword = registerFormDTO.getVerifyPassword();
        if (!password.equals(verifyPassword)) {
            errors.rejectValue("password", "passwords.mismatch", "Passwords do not match");
            model.addAttribute("title", "Register");
            return "register";
        }

        //create new user with form data
        User newUser = new User(registerFormDTO.getUsername(), registerFormDTO.getPassword());

        //save user to database
        userRepository.save(newUser);

        // create new user session
        setUserInSession(request.getSession(), newUser);

        //redirect to home page
        return "redirect:";
    }

    //display login form
    @GetMapping("/login")
    public String displayLoginForm(Model model) {
        model.addAttribute(new LoginFormDTO());
        model.addAttribute("title", "Log In");
        return "login";
    }

    //process login form
    @PostMapping("/login")
    public String processLoginForm(@ModelAttribute @Valid LoginFormDTO loginFormDTO,
                                   Errors errors, HttpServletRequest request,
                                   Model model) {

        //if validation errors, re-render login
        if (errors.hasErrors()) {
            model.addAttribute("title", "Log In");
            return "login";
        }

        //return error if database does not contain user with submitted username, re-render
        User theUser = userRepository.findByUsername(loginFormDTO.getUsername());
        if (theUser == null) {
            errors.rejectValue("username", "user.invalid", "The given username does not exist");
            model.addAttribute("title", "Log In");
            return "login";
        }

        //return error if submitted password does not match encoded password attached to username in the form, re-render
        String password = loginFormDTO.getPassword();
        if (!theUser.isMatchingPassword(password)) {
            errors.rejectValue("password", "password.invalid", "Invalid password");
            model.addAttribute("title", "Log In");
            return "login";
        }

        //create new user session if passes all checks
        setUserInSession(request.getSession(), theUser);
        return "redirect:";
    }

    //handle logout
    @GetMapping("/logout")

    //invalidate session data from request object
    public String logout(HttpServletRequest request){
        request.getSession().invalidate();

        //return user to login form
        return "redirect:/login";
    }


}
