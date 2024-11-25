package v1.domain.repository;

import v1.domain.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<User, Integer> {
    Boolean existsByUsername(String username);

    User findByUsername(String username);
}
