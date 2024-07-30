package com.rothnak.springsecurityjwt.repository;

import com.rothnak.springsecurityjwt.model.UserInfm;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<UserInfm, Integer> {
    Optional<UserInfm> findByEmail(String email);
}
