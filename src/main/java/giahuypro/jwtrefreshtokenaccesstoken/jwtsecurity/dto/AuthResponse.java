package giahuypro.jwtrefreshtokenaccesstoken.jwtsecurity.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class AuthResponse {
    private String tokenType;
    private String accessToken;
    @JsonIgnore// dùng để bỏ qua khi trả về front end (tránh lộ refresh token)
    private String refreshToken;
}
