package giahuypro.jwtrefreshtokenaccesstoken.jwtsecurity.service;

import giahuypro.jwtrefreshtokenaccesstoken.jwtsecurity.dto.AuthResponse;
import giahuypro.jwtrefreshtokenaccesstoken.jwtsecurity.dto.LoginRequest;
import giahuypro.jwtrefreshtokenaccesstoken.jwtsecurity.dto.RegisterRequest;
import giahuypro.jwtrefreshtokenaccesstoken.jwtsecurity.entity.RefreshToken;
import giahuypro.jwtrefreshtokenaccesstoken.jwtsecurity.entity.Role;
import giahuypro.jwtrefreshtokenaccesstoken.jwtsecurity.entity.User;
import giahuypro.jwtrefreshtokenaccesstoken.jwtsecurity.repository.RefreshTokenRepo;
import giahuypro.jwtrefreshtokenaccesstoken.jwtsecurity.repository.RoleRepository;
import giahuypro.jwtrefreshtokenaccesstoken.jwtsecurity.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

@Service
public class AuthService {
    @Autowired
    private  UserRepository userRepository;
    @Autowired
    private  PasswordEncoder passwordEncoder;
    @Autowired
    private  AuthenticationManager authenticationManager;
    @Autowired
    private  JwtService jwtService;

    @Autowired
    private RoleRepository roleRepository;
    @Value("${app.jwt.refresh-expiration}")
    private Long refreshTokenDurationMs;
    @Autowired
    private RefreshTokenRepo refreshTokenRepo;


    public RefreshToken createRefreshToken(User user) {
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUser(user);
        refreshToken.setToken(UUID.randomUUID().toString());
        refreshToken.setExpiryDate(Instant.now().plusMillis(refreshTokenDurationMs));
        return refreshTokenRepo.save(refreshToken);
    }

    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepo.findByToken(token);
    }

    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.getExpiryDate().isBefore(Instant.now())) {
            refreshTokenRepo.delete(token);
            throw new RuntimeException("Refresh token was expired. Please login again.");
        }
        return token;
    }

    public void deleteByUser(User user) {
        refreshTokenRepo.deleteByUser(user);
    }
    public AuthResponse login(LoginRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
        );

        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new RuntimeException("User not found after authentication"));

        String accessToken = jwtService.generateAccessToken(user);
        RefreshToken refreshToken = createRefreshToken(user);

        return new AuthResponse("Bearer", accessToken, refreshToken.getToken());
    }

    public String register(RegisterRequest req) {
        if (userRepository.existsByUsername(req.getUsername())) {
            throw new RuntimeException("Username already taken");
        }

        User user = new User();
        user.setFullName(req.getFullName());
        user.setUsername(req.getUsername());
        user.setPassword(passwordEncoder.encode(req.getPassword()));

        Set<Role> rolesSet = new HashSet<>();
        Role defaultRole = roleRepository.findByName("USER")
                .orElseGet(() -> {
                    Role r = new Role();
                    r.setName("USER");
                    return roleRepository.save(r);
                });
        rolesSet.add(defaultRole);
        user.setRoles(rolesSet);

        userRepository.save(user);

        // 🔴 Không tạo token ở đây nữa
        return "User registered successfully";
    }

}
