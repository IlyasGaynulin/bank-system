package ru.itpark.models;

import javax.persistence.*;

@Entity
@Table(name = "itpark_history_operations")
public class HistoryOperations {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;

    @Column
    private int owner_id;

    @Column
    private String message;

    public HistoryOperations() {
    }

    public HistoryOperations(int owner_id, String message) {
        this.owner_id = owner_id;
        this.message = message;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public int getOwner_id() {
        return owner_id;
    }

    public void setOwner_id(int owner_id) {
        this.owner_id = owner_id;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }
}
