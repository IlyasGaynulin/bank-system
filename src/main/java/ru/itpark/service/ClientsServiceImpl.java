package ru.itpark.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.itpark.dao.AccountsDao;
import ru.itpark.dao.ClientsDao;
import ru.itpark.dao.HistoryOperationsDao;
import ru.itpark.dto.ClientDataForRegistrationDto;
import ru.itpark.dto.ClientDto;
import ru.itpark.models.Account;
import ru.itpark.models.Client;
import ru.itpark.models.HistoryOperations;
import ru.itpark.models.TransferMessage;
import ru.itpark.security.utils.TokenGenerator;

import java.util.List;

import static ru.itpark.converters.Converter.convert;

@Service
public class ClientsServiceImpl implements ClientsService{

    @Autowired
    private ClientsDao clientsDao;

    @Autowired
    private AccountsDao accountsDao;

    @Autowired
    private TokenGenerator generator;

    @Autowired
    private HistoryOperationsDao historyOperationsDao;

    @Autowired
    private AccountsService accountsService;

    private PasswordEncoder encoder = new BCryptPasswordEncoder();

    public List<ClientDto> getClients() {
        List<Client> clients = clientsDao.findAll();
        return convert(clients);
    }

    public List<Account> getAccounts(String login) {
        Client client = clientsDao.findByLogin(login);
        return client.getAccounts();
    }

    public ClientDto registerClient(ClientDataForRegistrationDto registrationData) {
        Client client = new Client(
            registrationData.getLogin(),
            encoder.encode(registrationData.getPassword()),
            registrationData.getAge(),
            registrationData.getName()
        );
        Client savedClient = clientsDao.save(client);

        return convert(savedClient);
    }

    @Transactional
    public String login(String login, String password) {
        Client registeredClient = clientsDao.findByLogin(login);
        if(registeredClient != null) {
            if(encoder.matches(password, registeredClient.getPasswordHash())) {
                String token = generator.generate();
                clientsDao.updateToken(registeredClient.getId(), token);
                return token;
            }
        }
        return null;
    }

    public ClientDto getClient(String login) {
        Client client = clientsDao.findByLogin(login);
        return convert(client);
    }

    public Client takeClient(String login) {
        return clientsDao.findByLogin(login);
    }

    @Transactional
    public Account addAccountToClient(String login, Account account) {
        Client client = clientsDao.findByLogin(login);
        account.setOwnerId(client.getId());
        Account savedAccount = accountsDao.save(account);
        HistoryOperations historyOperations = new HistoryOperations(account.getOwnerId(), "Вы создали счёт: " + account.getName() + ". Была начислена начальная сумма денег.");
        historyOperationsDao.save(historyOperations);
        return savedAccount;
    }

    public String getAllMoney(String login) {
        Client client = clientsDao.findByLogin(login);
        List<Account> accounts = client.getAccounts();
        int result = 0;
        for(Account a : accounts) {
            result += a.getBalance();
        }
        return String.valueOf(result);
    }

    @Transactional
    public void tokenNull(String login) {
        Client client = clientsDao.findByLogin(login);
        client.setToken(null);
        clientsDao.save(client);
    }
    @Transactional
    public void transferMoney(TransferMessage transferMessage) {
        Client fromClient = takeClient(transferMessage.getFromLogin());
        Client addressClient = takeClient(transferMessage.getAddressLogin());
        List<Account> accounts = addressClient.getAccounts();
        accountsService.spendMoney(fromClient.getId(), transferMessage.getHowMuch());
        accountsService.addMoney(accounts.get(0).getId(), transferMessage.getHowMuch());
    }
}
