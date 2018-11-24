package ru.itpark.dao;

import org.springframework.data.jpa.repository.JpaRepository;
import ru.itpark.models.HistoryOperations;

public interface HistoryOperationsDao extends JpaRepository<HistoryOperations, Integer> {
}
