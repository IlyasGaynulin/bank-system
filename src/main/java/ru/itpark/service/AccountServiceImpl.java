package ru.itpark.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.itpark.dao.AccountsDao;
import ru.itpark.dao.ClientsDao;
import ru.itpark.dao.HistoryOperationsDao;
import ru.itpark.models.Account;
import ru.itpark.models.Client;
import ru.itpark.models.HistoryOperations;

import java.util.List;

@Service
public class AccountServiceImpl implements AccountsService {

    @Autowired
    private AccountsDao accountsDao;

    @Autowired
    private HistoryOperationsDao historyOperationsDao;

    @Autowired
    private ClientsDao clientsDao;


    @Transactional
    public void addMoney(int accountId, int money) {
        Account account = accountsDao.findById(accountId);
        accountsDao.updateBalance(accountId, account.getBalance() + money);
        HistoryOperations historyOperations = new HistoryOperations(account.getOwnerId(), "На ваш счёт " + account.getName() + " было зачислено " + money + "рублей.");
        historyOperationsDao.save(historyOperations);
    }

    @Transactional
    public boolean spendMoney(int accountId, int money) {
        Account account = accountsDao.findById(accountId);
        if(account.getBalance() > money) {
            accountsDao.updateBalance(accountId, account.getBalance() - money);
            HistoryOperations historyOperations = new HistoryOperations(account.getOwnerId(), "С вашего счёта " + account.getName() + " было списано " + money + "рублей.");
            historyOperationsDao.save(historyOperations);
            return true;
        } else {
            return false;
        }
    }

    public List<Account> getAccountsByClient(String login) {
        Client client = clientsDao.findByLogin(login);
        return client.getAccounts();
    }


}
