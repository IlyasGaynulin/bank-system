package ru.itpark.security.details;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import ru.itpark.dao.ClientsDao;
import ru.itpark.models.Client;

import java.util.ArrayList;
import java.util.List;

// класс, который обеспечивает доступ
// к данным авторизации
public class ClientDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private ClientsDao clientsDao;

    // загружает авторизационные данные пользователя по его username
    @Override
    public UserDetails loadUserByUsername(String token) throws UsernameNotFoundException {
        // проверяем, есть ли вообще такой токен в системе
        if (clientsDao.isExistToken(token)) {
            Client client = clientsDao.findByToken(token);
            List<GrantedAuthority> authorities = createGrantedAuthorities();
            return new ClientDetailsImpl(client.getLogin(), client.getPasswordHash(), authorities);
        }
        return null;
    }

    public static List<GrantedAuthority> createGrantedAuthorities() {
        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority("USER"));
        return authorities;
    }
}
