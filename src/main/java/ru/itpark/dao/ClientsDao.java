package ru.itpark.dao;

import org.springframework.data.jpa.repository.JpaRepository;

import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import ru.itpark.models.Client;

import java.util.List;

public interface ClientsDao extends JpaRepository<Client, Integer> {
    List<Client> findAll();

    @Query("select count(client) > 0 from Client client where client.token = ?1")
    boolean isExistToken(String token);

    Client findByToken(String token);

    Client findByLogin(String login);

    @Modifying
    @Query("update Client client set client.token = ?2 where client.id = ?1")
    void updateToken(int id, String token);
}
