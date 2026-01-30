package giahuypro.jwtrefreshtokenaccesstoken.jwtsecurity.service;

import giahuypro.jwtrefreshtokenaccesstoken.jwtsecurity.entity.Role;
import giahuypro.jwtrefreshtokenaccesstoken.jwtsecurity.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
@Slf4j
public class JwtService {

    @Value("${app.jwt.secret}")
    private String secretKey;

    @Value("${app.jwt.expiration}")
    private long accessTokenExpiration;

    @Value("${app.jwt.refresh-expiration}")
    private long refreshTokenExpiration;

    private Key getSignKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
    // Các chức năng xử lý JWT và kiểm tra tính hợp lệ của token
    // Các hàm để trích xuất thông tin từ token và xác thực token
    //1. function lấy thông tin  claims từ token
    public Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
    //2. hàm này 1 công cụ: để lấy 1 thông tin cụ thể từ claims
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }
    //3. hàm lấy username từ token
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    //  4.1 hàm lấy thời gian hết hạn từ token
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }
    //  4.2 Các hàm này sử dụng các chức năng trích xuất làm ở trên để kiểm tra token có hợp lệ hay không
    // before == < , after == >
    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }
    //4.3
    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
    // Các hàm để tạo token
//  hàm để tạo token  lấy input từ  hàm generateAccessToken trong service
    private String createToken(Map<String, Object> claims, String subject, long expiration) {
        return
                Jwts.builder() // Tạo bộ khung JWT
                .setClaims(claims) // gắn thông tin claims
                .setSubject(subject) // gắn username(email ...)
                .setIssuedAt(new Date(System.currentTimeMillis())) // gắn thời gian tạo token
                .setExpiration(new Date(System.currentTimeMillis() + expiration)) // gắn thời gian hết hạn
                .signWith(getSignKey(), SignatureAlgorithm.HS256)// ký token bằng thuật toán HS256 và key bí mật
                .compact(); // tạo chuỗi token hoàn chỉnh => đó chính là Accesstoken
    }
    // hàm này tạo access token bằng cách thiết lập claims cung cấp username(email ...) và thời gian hết hạn
    public String generateAccessToken(User user) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", user.getId());
//        claims.put("username", user.getUsername());
        claims.put("roles", user.getRoles().stream().map(Role::getName).toArray());
        return createToken(claims, user.getUsername(), accessTokenExpiration);
    }


}
