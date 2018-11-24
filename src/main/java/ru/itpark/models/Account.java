package ru.itpark.models;

import javax.persistence.*;
import java.util.List;

@Entity
@Table(name = "itpark_account")
public class Account {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;

    @Column
    private String name;

    @Column
    private int balance;

    @Column(name = "owner_id")
    private int ownerId;

    public Account() {
    }

    public Account(String name, int ownerId) {
        this.name = name;
        this.ownerId = ownerId;
    }




    public Account(int balance) {
        this.balance = balance;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public int getBalance() {
        return balance;
    }

    public void setBalance(int balance) {
        this.balance = balance;
    }

    public int getOwnerId() {
        return ownerId;
    }

    public void setOwnerId(int ownerId) {
        this.ownerId = ownerId;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
