package ru.itpark.service;

import ru.itpark.dto.ClientDataForRegistrationDto;
import ru.itpark.dto.ClientDto;
import ru.itpark.models.Account;
import ru.itpark.models.Client;
import ru.itpark.models.TransferMessage;

import java.util.List;

public interface ClientsService {
    List<ClientDto> getClients();
    List<Account> getAccounts(String login);

    ClientDto registerClient(ClientDataForRegistrationDto registrationData);

    String login(String login, String password);

    ClientDto getClient(String login);

    Client takeClient(String login);

    Account addAccountToClient(String login, Account account);

    String getAllMoney(String login);

    void tokenNull(String login);

    void transferMoney(TransferMessage transferMessage);
}
