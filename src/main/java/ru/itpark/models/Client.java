package ru.itpark.models;

import javax.persistence.*;
import java.util.List;

@Entity
@Table(name="itpark_client")
public class Client {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;

    @Column
    private String login;

    @Column(name = "password_hash")
    private String passwordHash;

    @Column
    private String name;

    @Column
    private int age;

    @Column
    private String token;

    @OneToMany
    @JoinTable(name = "itpark_account",
            joinColumns =
            @JoinColumn(name = "owner_id"),
            inverseJoinColumns =
            @JoinColumn(name = "id"))
    private List<Account> accounts;

    @OneToMany
    @JoinTable(name = "itpark_history_operations",
            joinColumns =
            @JoinColumn(name = "owner_id"),
            inverseJoinColumns =
            @JoinColumn(name = "id"))
    private List<HistoryOperations> historyOperations;

    public Client() {
    }

    public Client(String login, String passwordHash, int age, String name) {
        this.login = login;
        this.passwordHash = passwordHash;
        this.age = age;
        this.name = name;
    }

    public Client(String login, String passwordHash, int age, String name, String token) {
        this.login = login;
        this.passwordHash = passwordHash;
        this.age = age;
        this.name = name;
        this.token = token;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getLogin() {
        return login;
    }

    public void setLogin(String login) {
        this.login = login;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public void setPasswordHash(String passwordHash) {
        this.passwordHash = passwordHash;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public int getAge() {
        return age;
    }

    public void setAge(int age) {
        this.age = age;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public List<Account> getAccounts() {
        return accounts;
    }

    public void setAccounts(List<Account> accounts) {
        this.accounts = accounts;
    }

    public List<HistoryOperations> getHistoryMessages() {
        return historyOperations;
    }

    public void setHistoryMessages(List<HistoryOperations> historyOperations) {
        this.historyOperations = historyOperations;
    }
}
