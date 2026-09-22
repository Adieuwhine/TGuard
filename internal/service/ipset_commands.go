package service

import (
	"fmt"
	"strings"

	"github.com/rs/zerolog"
)

type IpsetCommandService struct {
	logger zerolog.Logger
	cmdSvc *CommandService
}

func NewIpsetCommandService(logger zerolog.Logger, cmdSvc *CommandService) *IpsetCommandService {
	return &IpsetCommandService{
		logger: logger,
		cmdSvc: cmdSvc,
	}
}

type SetType string

const (
	SetTypeHashNet  SetType = "hash:net"
	SetTypeHashIP   SetType = "hash:ip"
	SetTypeHashMAC  SetType = "hash:mac"
	SetTypeHashPort SetType = "hash:port"
)

type Family string

const (
	FamilyIPv4 Family = "inet"
	FamilyIPv6 Family = "inet6"
)

type CreateSetOptions struct {
	Name     string
	Type     SetType
	Family   Family
	HashSize int
	MaxElem  int
	Timeout  int
	Comment  bool
}

func (s *IpsetCommandService) Create(opts CreateSetOptions) error {
	s.logger.Debug().
		Str("name", opts.Name).
		Str("type", string(opts.Type)).
		Str("family", string(opts.Family)).
		Msg("Creating ipset set")

	args := []string{"create", opts.Name, string(opts.Type)}

	if opts.Family != "" {
		args = append(args, "family", string(opts.Family))
	}

	if opts.HashSize > 0 {
		args = append(args, "hashsize", fmt.Sprintf("%d", opts.HashSize))
	}

	if opts.MaxElem > 0 {
		args = append(args, "maxelem", fmt.Sprintf("%d", opts.MaxElem))
	}

	if opts.Timeout > 0 {
		args = append(args, "timeout", fmt.Sprintf("%d", opts.Timeout))
	}

	if opts.Comment {
		args = append(args, "comment")
	}

	return s.cmdSvc.Run("ipset", args...)
}

func (s *IpsetCommandService) Destroy(name string) error {
	s.logger.Debug().Str("name", name).Msg("Destroying ipset set")
	return s.cmdSvc.Run("ipset", "destroy", name)
}

func (s *IpsetCommandService) Flush(name string) error {
	s.logger.Debug().Str("name", name).Msg("Flushing ipset set")
	return s.cmdSvc.Run("ipset", "flush", name)
}

func (s *IpsetCommandService) Add(setName, entry string) error {
	return s.cmdSvc.Run("ipset", "add", setName, entry)
}

func (s *IpsetCommandService) AddWithTimeout(setName, entry string, timeout int) error {
	return s.cmdSvc.Run("ipset", "add", setName, entry, "timeout", fmt.Sprintf("%d", timeout))
}

func (s *IpsetCommandService) AddWithComment(setName, entry, comment string) error {
	return s.cmdSvc.Run("ipset", "add", setName, entry, "comment", comment)
}

func (s *IpsetCommandService) Delete(setName, entry string) error {
	return s.cmdSvc.Run("ipset", "del", setName, entry)
}

func (s *IpsetCommandService) Test(setName, entry string) (bool, error) {
	err := s.cmdSvc.Run("ipset", "test", setName, entry)
	if err != nil {
		if strings.Contains(err.Error(), "is NOT in set") {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (s *IpsetCommandService) List(name string) (string, error) {
	s.logger.Debug().Str("name", name).Msg("Listing ipset set")
	return s.cmdSvc.RunOutput("ipset", "list", name)
}

func (s *IpsetCommandService) ListAll() (string, error) {
	s.logger.Debug().Msg("Listing all ipset sets")
	return s.cmdSvc.RunOutput("ipset", "list")
}

func (s *IpsetCommandService) Exists(name string) bool {
	_, err := s.cmdSvc.RunOutputQuiet("ipset", "list", name)
	return err == nil
}

func (s *IpsetCommandService) Save(path string) error {
	s.logger.Info().Str("path", path).Msg("Saving ipset configuration")
	return s.cmdSvc.RunShell(fmt.Sprintf("ipset save > %s", path))
}

func (s *IpsetCommandService) SaveSet(name, path string) error {
	s.logger.Info().
		Str("name", name).
		Str("path", path).
		Msg("Saving ipset set")
	return s.cmdSvc.RunShell(fmt.Sprintf("ipset save %s > %s", name, path))
}

func (s *IpsetCommandService) Restore(path string) error {
	s.logger.Info().Str("path", path).Msg("Restoring ipset configuration")
	return s.cmdSvc.RunShell(fmt.Sprintf("ipset restore -exist < %s", path))
}

func (s *IpsetCommandService) RestoreForce(path string) error {
	s.logger.Info().Str("path", path).Msg("Force restoring ipset configuration")
	return s.cmdSvc.RunShell(fmt.Sprintf("ipset restore < %s", path))
}

func (s *IpsetCommandService) Rename(oldName, newName string) error {
	s.logger.Info().
		Str("old_name", oldName).
		Str("new_name", newName).
		Msg("Renaming ipset set")
	return s.cmdSvc.Run("ipset", "rename", oldName, newName)
}

func (s *IpsetCommandService) Swap(setName1, setName2 string) error {
	s.logger.Info().
		Str("set1", setName1).
		Str("set2", setName2).
		Msg("Swapping ipset sets")
	return s.cmdSvc.Run("ipset", "swap", setName1, setName2)
}

func (s *IpsetCommandService) GetVersion() (string, error) {
	return s.cmdSvc.RunOutput("ipset", "version")
}

func (s *IpsetCommandService) FlushAll() error {
	s.logger.Info().Msg("Flushing all ipset sets")
	return s.cmdSvc.Run("ipset", "flush")
}

func (s *IpsetCommandService) DestroyAll() error {
	s.logger.Info().Msg("Destroying all ipset sets")
	return s.cmdSvc.Run("ipset", "destroy")
}

func (s *IpsetCommandService) CreateHashNet(name string, family Family, hashSize, maxElem int) error {
	return s.Create(CreateSetOptions{
		Name:     name,
		Type:     SetTypeHashNet,
		Family:   family,
		HashSize: hashSize,
		MaxElem:  maxElem,
	})
}

func (s *IpsetCommandService) CreateHashIP(name string, family Family, hashSize, maxElem int) error {
	return s.Create(CreateSetOptions{
		Name:     name,
		Type:     SetTypeHashIP,
		Family:   family,
		HashSize: hashSize,
		MaxElem:  maxElem,
	})
}
