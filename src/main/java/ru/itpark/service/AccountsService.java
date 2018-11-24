package ru.itpark.service;

import ru.itpark.models.Account;

import java.util.List;

public interface AccountsService {
    void addMoney(int accountId, int money);
    boolean spendMoney(int accountId, int money);
    List<Account> getAccountsByClient(String login);
}
