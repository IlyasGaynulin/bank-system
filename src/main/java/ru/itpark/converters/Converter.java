package ru.itpark.converters;

import ru.itpark.dto.ClientDto;
import ru.itpark.models.Client;

import java.util.List;
import java.util.stream.Collectors;

public class Converter {
    public static ClientDto convert(Client model) {
        return new ClientDto(model.getId(), model.getName(), model.getAge(), model.getLogin());
    }

    public static List<ClientDto> convert(List<Client> models) {
        return models.stream()
                .map(client -> convert(client)).collect(Collectors.toList());
    }
}
