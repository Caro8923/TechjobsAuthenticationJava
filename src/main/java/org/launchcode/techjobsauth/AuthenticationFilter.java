package org.launchcode.codingevents;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.launchcode.techjobsauth.controllers.AuthenticationController;
import org.launchcode.techjobsauth.models.data.UserRepository;
import org.launchcode.techjobsauth.models.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.servlet.HandlerInterceptor;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

public class AuthenticationFilter implements HandlerInterceptor {

    @Autowired
    UserRepository userRepository;

    @Autowired
    AuthenticationController authenticationController;

    private static final List<String> whitelist = Arrays.asList("/login", "/register", "/logout", "/css");


    //paths that can be accessed without a user session
    private static boolean isWhitelisted(String path) {
        for (String pathRoot : whitelist) {
            if (path.startsWith(pathRoot)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean preHandle(HttpServletRequest request,
                             HttpServletResponse response,
                             Object handler) throws IOException {

        //checks whitelist status of current request object
        if (isWhitelisted(request.getRequestURI())) {
            // returning true indicates that the request may proceed
            return true;
        }


        //look for session and user status
        HttpSession session = request.getSession();
        User user = authenticationController.getUserFromSession(session);

        // The user is logged in (user exists)
        if (user != null) {
            return true;
        }

        // The user is NOT logged in (user does not exist)
        response.sendRedirect("/login");
        return false;
    }

}