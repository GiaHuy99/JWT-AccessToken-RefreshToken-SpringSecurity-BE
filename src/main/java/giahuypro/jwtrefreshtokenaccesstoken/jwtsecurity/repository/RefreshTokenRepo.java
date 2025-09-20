package giahuypro.jwtrefreshtokenaccesstoken.jwtsecurity.repository;

import giahuypro.jwtrefreshtokenaccesstoken.jwtsecurity.entity.RefreshToken;
import giahuypro.jwtrefreshtokenaccesstoken.jwtsecurity.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RefreshTokenRepo extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByToken(String token);
    void deleteByUser(User user);
}
