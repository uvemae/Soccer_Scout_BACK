package com.football.managerback.manager.user.login;

import com.football.managerback.domain.user.User;
import com.football.managerback.domain.user.UserMapper;
import com.football.managerback.domain.user.UserRepository;
import com.football.managerback.infrastructure.exception.ForbiddenException;
import com.football.managerback.infrastructure.security.JwtService;
import com.football.managerback.manager.Status;
import com.football.managerback.manager.user.login.dto.LoginResponse;
import lombok.AllArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

import static com.football.managerback.infrastructure.error.Error.INCORRECT_CREDENTIALS;

@Service
@AllArgsConstructor
public class LoginService {

    private final UserRepository userRepository;
    private final UserMapper userMapper;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    public LoginResponse login(String username, String password) {
        Optional<User> optionalUser = userRepository.findUserByUsername(username, Status.ACTIVE);

        if (optionalUser.isEmpty() || !passwordEncoder.matches(password, optionalUser.get().getPassword())) {
            throw new ForbiddenException(INCORRECT_CREDENTIALS.getMessage(), INCORRECT_CREDENTIALS.getErrorCode());
        }

        User user = optionalUser.get();
        LoginResponse loginResponse = userMapper.toLoginResponse(user);
        String token = jwtService.generateToken(user.getId(), user.getUsername(), user.getRole().getName());
        loginResponse.setToken(token);
        return loginResponse;
    }
}
