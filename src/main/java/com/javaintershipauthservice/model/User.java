package com.javaintershipauthservice.model;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import lombok.Data;
import lombok.EqualsAndHashCode;
import jakarta.persistence.*;
import java.util.List;
import jakarta.persistence.OneToMany;
import jakarta.persistence.CascadeType;



@Entity(name = "users")
@Table(name = "users")
@Data
@EqualsAndHashCode(callSuper = true)
public class User extends BaseAuditingEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_id", nullable = false, unique = true)
    private Long userId;

    @Column(name = "login", nullable = false)
    private String login;

    @Column(name = "password", nullable = false)
    private String password;

    @Column(name = "email", nullable = false)
    private String email;

    @Column(name = "active", nullable = false)
    private Boolean active;

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL)
    private List<Role> roles;

}
