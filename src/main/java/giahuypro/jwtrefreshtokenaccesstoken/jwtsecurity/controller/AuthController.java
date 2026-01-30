package giahuypro.jwtrefreshtokenaccesstoken.jwtsecurity.controller;

import giahuypro.jwtrefreshtokenaccesstoken.jwtsecurity.dto.AuthResponse;
import giahuypro.jwtrefreshtokenaccesstoken.jwtsecurity.dto.LoginRequest;
import giahuypro.jwtrefreshtokenaccesstoken.jwtsecurity.dto.RegisterRequest;
import giahuypro.jwtrefreshtokenaccesstoken.jwtsecurity.entity.RefreshToken;
import giahuypro.jwtrefreshtokenaccesstoken.jwtsecurity.service.AuthService;
import giahuypro.jwtrefreshtokenaccesstoken.jwtsecurity.service.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    @Autowired
    private  AuthService authService;

    @Value("${app.jwt.refresh-expiration}")
    private Long cookieDuration;
    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest req) {
         authService.register(req);
        return ResponseEntity.ok("User registered successfully");
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest req) {
        // 1. Gọi service để lấy thông tin xác thực (bao gồm cả Access & Refresh Token)
        AuthResponse resp = authService.login(req);

        // 2. Tạo HttpOnly Cookie cho Refresh Token
        ResponseCookie refreshCookie = ResponseCookie.from("refresh_token", resp.getRefreshToken())
                .httpOnly(true)           // Quan trọng: JS không thể truy cập
                .secure(false)             // Set true nếu chạy trên HTTPS (Production), false nếu chạy localhost (Dev)
                .path("/")                // Cookie có hiệu lực trên toàn bộ domain
                .maxAge(cookieDuration) // Thời gian sống (ví dụ: 7 ngày), nên khớp với hạn của refreshToken
                .sameSite("Strict")       // Chống CSRF
                .build();
        // 4. Trả về ResponseEntity kèm Header Set-Cookie
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, refreshCookie.toString())
                .body(resp); // Body lúc này chỉ cần chứa accessToken
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(
            @CookieValue(name = "refresh_token", required = false) String refreshToken
    ) {
        // 1. Kiểm tra xem Cookie có tồn tại không
        if (refreshToken == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Refresh Token is missing in Cookie!");
        }

        try {
            // 2. Gọi Service để lấy Access Token mới
            // Lưu ý: Service lúc này chỉ nên trả về Access Token thôi
            Map<String, String> response = authService.refreshAccessToken(refreshToken);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            // 3. Nếu token lỗi (hết hạn, fake...), nên xóa cookie đi để user đăng nhập lại
            ResponseCookie cleanCookie = ResponseCookie.from("refresh_token", "")
                    .path("/")
                    .maxAge(0)
                    .build();

            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .header(HttpHeaders.SET_COOKIE, cleanCookie.toString())
                    .body(e.getMessage());
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@CookieValue(name = "refresh_token", required = false) String refreshToken) {

        // 1. Xử lý xóa trong Database (nếu có token)
        if (refreshToken != null) {
            // Có thể bọc try-catch nếu service ném lỗi khi không tìm thấy token
            try {
                authService.logout(refreshToken);
            } catch (Exception e) {
                // Log lỗi nếu cần, nhưng thường logout nên luôn trả về thành công
            }
        }

        // 2. Tạo cookie mới có thời gian sống = 0 để XÓA cookie ở trình duyệt
        ResponseCookie cleanCookie = ResponseCookie.from("refresh_token", "")
                .httpOnly(true)
                .secure(true)
                .path("/")
                .maxAge(0) // Quan trọng: 0 có nghĩa là hết hạn ngay lập tức
                .sameSite("Strict")
                .build();

        // 3. Trả về response kèm header xóa cookie
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cleanCookie.toString())
                .body(Map.of("message", "Logged out successfully"));
    }
}
