package com.kunthea.jwt.service;

import com.kunthea.jwt.repository.UserRepositories;
import com.kunthea.jwt.entity.User;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class UserService {
    private final UserRepositories userRepository;

    public UserService(UserRepositories userRepository) {
        this.userRepository = userRepository;
    }

    public List<User> allUsers() {
        List<User> users = new ArrayList<>();

        userRepository.findAll().forEach(users::add);

        return users;
    }
}
