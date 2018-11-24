package ru.itpark.models;

import com.sun.xml.internal.ws.developer.UsesJAXBContext;
import org.springframework.data.jpa.repository.JpaRepository;

import javax.persistence.*;

@Entity
@Table(name="transfer_message")
public class TransferMessage {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;

    @Column(name = "how_much")
    private int howMuch;

    @Column(name = "from_login")
    private String fromLogin;

    @Column(name = "from_account")
    private String fromAccount;

    @Column(name = "address_login")
    private String addressLogin;

    public TransferMessage() {
    }

    public TransferMessage(int howMuch, String fromLogin, String fromAccount, String addressLogin) {
        this.howMuch = howMuch;
        this.fromLogin = fromLogin;
        this.fromAccount = fromAccount;
        this.addressLogin = addressLogin;
    }

    public TransferMessage(int howMuch, String fromAccount, String addressLogin) {
        this.howMuch = howMuch;
        this.fromAccount = fromAccount;
        this.addressLogin = addressLogin;
    }

    public int getId() {
        return id;
    }

    public int getHowMuch() {
        return howMuch;
    }


    public String getFromLogin() {
        return fromLogin;
    }

    public String getAddressLogin() {
        return addressLogin;
    }

    public String getFromAccount() {
        return fromAccount;
    }

    public void setFromLogin(String fromLogin) {
        this.fromLogin = fromLogin;
    }
}
