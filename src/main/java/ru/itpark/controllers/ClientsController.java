package ru.itpark.controllers;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.method.P;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;
import ru.itpark.dto.ClientDataForRegistrationDto;
import ru.itpark.dto.ClientDto;
import ru.itpark.models.Account;
import ru.itpark.models.TransferMessage;
import ru.itpark.service.AccountsService;
import ru.itpark.service.ClientsService;

import java.util.List;

@RestController
public class ClientsController {

    @Autowired
    private ClientsService clientsService;

    @Autowired
    private AccountsService accountsService;



    @GetMapping("/clients")
    public List<ClientDto> getClients() {
        return clientsService.getClients();
    }


    @PostMapping("/clients")
    public ClientDto register(@RequestBody ClientDataForRegistrationDto registrationData) {
        return clientsService.registerClient(registrationData);
    }

    @PostMapping("/login")
    public ResponseEntity<Object> login(@RequestHeader("password") String password,
                                        @RequestHeader("login") String login) {
        String token = clientsService.login(login, password);
        HttpHeaders headers = new HttpHeaders();
        if(token != null) {
            headers.add("Auth-Token", token);
            headers.add("Logon-User", login);
            headers.add("Status", "accepted");
        } else {
            headers.add("Status", "decline");
        }
        return new ResponseEntity<>(null, headers, HttpStatus.ACCEPTED);
    }

    @PostMapping(value = "clients/{client-nickname}/accounts")
    public ResponseEntity<Object> addAccountToUser(@PathVariable("client-nickname") String login,
                                 @RequestBody Account account) {
        Account savedAccount = clientsService.addAccountToClient(login, account);
        accountsService.addMoney(savedAccount.getId(), 1000);
        return new ResponseEntity<Object>(HttpStatus.ACCEPTED);
    }



    @PostMapping("clients/{client-nickname}/transfer")
    public void transferMoney(@RequestBody TransferMessage transferMessage,
                              @PathVariable("client-nickname") String login) {
        transferMessage.setFromLogin(login);
        clientsService.transferMoney(transferMessage);
    }
}