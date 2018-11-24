package ru.itpark.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.*;
import ru.itpark.dto.ClientDto;
import ru.itpark.models.Account;
import ru.itpark.models.Client;
import ru.itpark.models.HistoryOperations;
import ru.itpark.service.ClientsService;

import java.util.Collection;
import java.util.Collections;
import java.util.List;

@Controller
public class FreemarkerController {

    @Autowired
    private ClientsService clientsService;



    @GetMapping("/signup")
    public String index(@ModelAttribute("signup")ModelMap model) throws Exception {
        return "registration";
    }

    @GetMapping("/signin")
    public String signin(@ModelAttribute("signin")ModelMap model) throws Exception {
        return "authorization";
    }

    @GetMapping("/clients/{client-nickname}")
    public String getUser(@ModelAttribute("cabinet")ModelMap model,
                          @PathVariable("client-nickname") String login) throws Exception {
        Client client = clientsService.takeClient(login);
        model.addAttribute("client", client);
        List<HistoryOperations> historyOperations = client.getHistoryMessages();
        Collections.reverse(historyOperations);
        model.addAttribute("history", historyOperations);
        model.addAttribute("balance", clientsService.getAllMoney(login));
        return "cabinet";
    }

    @GetMapping(value = "clients/{client-nickname}/accounts")
    public String addAccountToUser(@ModelAttribute("accounts")ModelMap model,
                                                   @PathVariable("client-nickname") String login) throws Exception {
        List<Account> accounts = clientsService.getAccounts(login);
        model.addAttribute("accounts", accounts);
        model.addAttribute("client", clientsService.getClient(login));
        model.addAttribute("balance", clientsService.getAllMoney(login));
        model.addAttribute("count",accounts.size());
        return "accounts";
    }

    @GetMapping("/clients/{client-nickname}/logout")
    public String getUser(@PathVariable("client-nickname") String login) throws Exception {
        clientsService.tokenNull(login);
        return "logout";
    }

    @GetMapping(value = "clients/{client-nickname}/transfer")
    public String transfer(@ModelAttribute("transfer")ModelMap model,
                           @PathVariable("client-nickname") String login) throws Exception {
        model.addAttribute("client", clientsService.getClient(login));
        model.addAttribute("balance", clientsService.getAllMoney(login));
        return "transfer";
    }
}
