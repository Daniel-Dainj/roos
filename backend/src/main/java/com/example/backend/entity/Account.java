package com.example.backend.entity;

import lombok.Data;

@Data
public class Account {
    int id;
    String email;
    String username;
    String password;
}
