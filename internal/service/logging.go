package service

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/rs/zerolog"
)

type LoggingService struct {
	logger zerolog.Logger
}

func NewLoggingService(logger zerolog.Logger) *LoggingService {
	return &LoggingService{
		logger: logger,
	}
}

func (s *LoggingService) Setup() error {
	s.logger.Info().Msg("Настройка логирования")

	if err := s.setupRsyslog(); err != nil {
		return fmt.Errorf("failed to setup rsyslog: %w", err)
	}

	if err := s.createLogFiles(); err != nil {
		return fmt.Errorf("failed to create log files: %w", err)
	}

	if err := s.setupLogrotate(); err != nil {
		return fmt.Errorf("failed to setup logrotate: %w", err)
	}

	if err := s.setupAggregationScript(); err != nil {
		return fmt.Errorf("failed to setup aggregation script: %w", err)
	}

	if err := s.setupCronJob(); err != nil {
		return fmt.Errorf("failed to setup cron job: %w", err)
	}

	if err := s.reloadRsyslog(); err != nil {
		s.logger.Warn().Err(err).Msg("Не удалось перезагрузить rsyslog, может потребоваться ручная перезагрузка")
	}

	s.logger.Info().Msg("Конфигурация логирования готова")
	s.logger.Info().Msg("  Сырые логи: /var/log/iptables-scanners-{ipv4,ipv6}.log")
	s.logger.Info().Msg("  Агрегированные: /var/log/iptables-scanners-aggregate.csv (с ASN/netname, обновляются каждые 30 сек)")
	s.logger.Info().Msg("  Rate limit: 10 entries/minute")
	s.logger.Info().Msg("  Проверить статус: systemctl status antiscan-aggregate.timer")

	return nil
}

func (s *LoggingService) setupRsyslog() error {
	if err := os.WriteFile(RsyslogConfigPath, []byte(RsyslogConfigTemplate), 0644); err != nil {
		return err
	}
	s.logger.Info().Str("path", RsyslogConfigPath).Msg("Конфиг rsyslog создан")
	return nil
}

func (s *LoggingService) createLogFiles() error {
	logFiles := []string{
		IPv4LogPath,
		IPv6LogPath,
	}

	for _, logFile := range logFiles {
		if _, err := os.Stat(logFile); os.IsNotExist(err) {
			f, err := os.Create(logFile)
			if err != nil {
				return fmt.Errorf("failed to create %s: %w", logFile, err)
			}
			f.Close()

			if err := exec.Command("chown", "syslog:adm", logFile).Run(); err != nil {
				s.logger.Warn().Err(err).Str("file", logFile).Msg("Failed to chown log file")
			}
			if err := exec.Command("chmod", "640", logFile).Run(); err != nil {
				s.logger.Warn().Err(err).Str("file", logFile).Msg("Failed to chmod log file")
			}

			s.logger.Info().Str("file", logFile).Msg("Создан лог файл")
		}
	}

	return nil
}

func (s *LoggingService) setupLogrotate() error {
	if err := os.WriteFile(LogrotateConfigPath, []byte(LogrotateConfigTemplate), 0644); err != nil {
		return err
	}

	s.logger.Info().Str("path", LogrotateConfigPath).Msg("Создан logrotate конфиг")
	return nil
}

func (s *LoggingService) setupAggregationScript() error {
	if err := os.WriteFile(AggregateLogsScriptPath, []byte(AggregateLogsScriptTemplate), 0755); err != nil {
		return fmt.Errorf("failed to write aggregator script: %w", err)
	}

	if err := exec.Command("chmod", "+x", AggregateLogsScriptPath).Run(); err != nil {
		return fmt.Errorf("failed to make script executable: %w", err)
	}

	s.logger.Info().Str("path", AggregateLogsScriptPath).Msg("Создан скрипт агрегирования логов")
	return nil
}

func (s *LoggingService) setupCronJob() error {
	if err := os.WriteFile(AggregateLogsServicePath, []byte(AggregateLogsServiceTemplate), 0644); err != nil {
		return err
	}
	s.logger.Info().Str("path", AggregateLogsServicePath).Msg("Создан systemd сервис")

	if err := os.WriteFile(AggregateLogsTimerPath, []byte(AggregateLogsTimerTemplate), 0644); err != nil {
		return err
	}
	s.logger.Info().Str("path", AggregateLogsTimerPath).Msg("Создан systemd timer")

	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		s.logger.Warn().Err(err).Msg("Не удалось перезапустить systemd daemon")
	}

	if err := exec.Command("systemctl", "enable", "antiscan-aggregate.timer").Run(); err != nil {
		s.logger.Warn().Err(err).Msg("Не удалось включить antiscan-aggregate")
	}

	if err := exec.Command("systemctl", "start", "antiscan-aggregate.timer").Run(); err != nil {
		s.logger.Warn().Err(err).Msg("Не удалось включить timer")
	}

	s.logger.Info().Msg("Systemd timer включен и запущен (каждые 30 секунд)")
	return nil
}

func (s *LoggingService) reloadRsyslog() error {
	if err := exec.Command("systemctl", "restart", "rsyslog").Run(); err != nil {
		return err
	}
	s.logger.Info().Msg("Rsyslog перезапущен")
	return nil
}
