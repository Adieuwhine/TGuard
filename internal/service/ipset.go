package service

import (
	"fmt"
	"os"

	"tguard/internal/domain"

	"github.com/rs/zerolog"
)

const (
	ipsetV4Name = "SCANNERS-BLOCK-V4"
	ipsetV6Name = "SCANNERS-BLOCK-V6"
)

type IpsetService struct {
	logger   zerolog.Logger
	cmdSvc   *CommandService
	ipsetCmd *IpsetCommandService
}

func NewIpsetService(logger zerolog.Logger, cmdSvc *CommandService) *IpsetService {
	return &IpsetService{
		logger:   logger,
		cmdSvc:   cmdSvc,
		ipsetCmd: NewIpsetCommandService(logger, cmdSvc),
	}
}

func (s *IpsetService) Setup() error {
	s.logger.Info().Msg("Установка наборов ipset")

	if err := s.setupSet(ipsetV4Name, "inet"); err != nil {
		return fmt.Errorf("failed to setup IPv4 set: %w", err)
	}

	if err := s.setupSet(ipsetV6Name, "inet6"); err != nil {
		return fmt.Errorf("failed to setup IPv6 set: %w", err)
	}

	s.logger.Info().Msg("Наборы ipset установлены")
	return nil
}

func (s *IpsetService) setupSet(name, family string) error {
	s.logger.Debug().Str("set", name).Msg("Проверка набора ipset")

	if s.ipsetCmd.Exists(name) {
		s.logger.Info().Str("set", name).Msg("Очищаем существующий набор")
		if err := s.ipsetCmd.Flush(name); err != nil {
			return fmt.Errorf("failed to flush set %s: %w", name, err)
		}
		s.logger.Info().Str("set", name).Msg("Set flushed")
	} else {
		s.logger.Info().Str("set", name).Str("family", family).Msg("Creating set")
		if err := s.ipsetCmd.CreateHashNet(name, Family(family), 1024, 65536); err != nil {
			return fmt.Errorf("failed to create set %s: %w", name, err)
		}
		s.logger.Info().Str("set", name).Msg("Set created")
	}

	return nil
}

func (s *IpsetService) Fill(networks *domain.NetworkList) error {
	s.logger.Info().
		Int("ipv4_count", networks.IPv4Count()).
		Int("ipv6_count", networks.IPv6Count()).
		Msg("Заполнение ipset списков")

	addedV4, errorsV4 := s.fillSet(ipsetV4Name, networks.IPv4Subnets, "IPv4")

	addedV6, errorsV6 := s.fillSet(ipsetV6Name, networks.IPv6Subnets, "IPv6")

	s.logger.Info().
		Int("ipv4_added", addedV4).
		Int("ipv4_errors", errorsV4).
		Int("ipv6_added", addedV6).
		Int("ipv6_errors", errorsV6).
		Msg("Наборы ipset заполнены")

	return nil
}

func (s *IpsetService) fillSet(setName string, subnets []string, label string) (added, errors int) {
	total := len(subnets)
	s.logger.Info().Int("total", total).Str("type", label).Msg("Добавление подсетей в ipset")

	for i, subnet := range subnets {
		if err := s.ipsetCmd.Add(setName, subnet); err == nil {
			added++
			if (i+1)%100 == 0 {
				s.logger.Debug().
					Int("progress", i+1).
					Int("total", total).
					Str("type", label).
					Msg("Progress")
			}
		} else {
			errors++
			s.logger.Warn().
				Err(err).
				Str("subnet", subnet).
				Str("set", setName).
				Msg("Failed to add subnet")
		}
	}

	return added, errors
}

func (s *IpsetService) Save(path string) error {
	s.logger.Info().Str("path", path).Msg("Сохранение конфигурации ipset")

	if err := s.ipsetCmd.Save(path); err != nil {
		return fmt.Errorf("failed to save ipset: %w", err)
	}

	s.logger.Info().Str("path", path).Msg("Конфигурация ipset сохранена")
	return nil
}

func (s *IpsetService) Restore(path string) error {
	s.logger.Info().Str("path", path).Msg("Загрузка конфигурации ipset")

	if err := s.ipsetCmd.Restore(path); err != nil {
		return fmt.Errorf("failed to restore ipset: %w", err)
	}

	s.logger.Info().Str("path", path).Msg("Конфигурация ipset загружена")
	return nil
}

func (s *IpsetService) CreateRestoreService() error {
	s.logger.Info().Msg("Создание systemd сервиса для загрузки конфигурации ipset")

	if err := os.WriteFile(IpsetRestoreServicePath, []byte(IpsetRestoreServiceTemplate), 0644); err != nil {
		return fmt.Errorf("failed to create systemd service: %w", err)
	}
	s.logger.Info().Str("path", IpsetRestoreServicePath).Msg("Создан systemd сервис")

	if err := s.cmdSvc.DaemonReload(); err != nil {
		s.logger.Warn().Err(err).Msg("Не удалось перезагрузить демон systemd")
	}

	if err := s.cmdSvc.EnableService("antiscan-ipset-restore.service"); err != nil {
		return fmt.Errorf("failed to enable service: %w", err)
	}
	s.logger.Info().Msg("Сервис systemd успешно включен")

	s.logger.Info().Msg("Ipset будет автоматически восстановлен на системном запуске перед запуском UFW")
	return nil
}
