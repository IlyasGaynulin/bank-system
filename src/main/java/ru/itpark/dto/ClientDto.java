package ru.itpark.dto;

public class ClientDto {
    private int id;
    private String name;
    private int age;
    private String login;

    public ClientDto(int id, String name, int age, String login) {
        this.id = id;
        this.name = name;
        this.age = age;
        this.login = login;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
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

    public String getLogin() {
        return login;
    }

    public void setLogin(String login) {
        this.login = login;
    }
}
