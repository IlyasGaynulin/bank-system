package ru.itpark.dao;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import ru.itpark.models.Account;

public interface AccountsDao extends JpaRepository<Account, Integer> {
    @Modifying
    @Query("update Account account set account.balance = ?2 where account.id = ?1")
    void updateBalance(int id, int value);

    Account findById(int id);
    Account findByName(String name);
}
