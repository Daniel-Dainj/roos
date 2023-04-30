package com.example.backend.mapper;

import com.example.backend.entity.Account;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;

@Mapper
public interface UserMapper {

    @Select("select * from db_account where username = #{text} or email = #{text}")
    Account findAccountByEmailOrName(String text);
}
