package org.launchcode.techjobsauth.models.data;

import org.launchcode.techjobsauth.models.User;
import org.springframework.data.repository.CrudRepository;

public interface UserRepository extends CrudRepository<User, Integer> {

    //special query method to find user by a username
    User findByUsername(String username);

}
