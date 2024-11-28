package v1.domain.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Setter
@Getter
public class UserEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;

    private String username;
    private String password;
    private String role;
}
