package hyperv

import (
	"bufio"
	"bytes"
	"errors"
	"os/exec"
	"strings"

	"fmt"

	"github.com/docker/machine/libmachine/log"
)

var powershell string

var (
	ErrPowerShellNotFound = errors.New("Powershell was not found in the path")
	ErrNotAdministrator   = errors.New("Hyper-v commands have to be run as an Administrator")
	ErrNotInstalled       = errors.New("Hyper-V PowerShell Module is not available")
)

func init() {
	powershell, _ = exec.LookPath("powershell.exe")
}

func cmdOut(args ...string) (string, error) {
	args = append([]string{"-NoProfile", "-NonInteractive"}, args...)
	cmd := exec.Command(powershell, args...)
	log.Debugf("[executing ==>] : %v %v", powershell, strings.Join(args, " "))
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	log.Debugf("[stdout =====>] : %s", stdout.String())
	log.Debugf("[stderr =====>] : %s", stderr.String())
	return stdout.String(), err
}

func Cmd(args ...string) error {
	_, err := cmdOut(args...)
	return err
}

func ParseLines(stdout string) []string {
	resp := []string{}

	s := bufio.NewScanner(strings.NewReader(stdout))
	for s.Scan() {
		resp = append(resp, s.Text())
	}

	return resp
}

func hypervAvailable() error {
	stdout, err := cmdOut("@(Get-Module -ListAvailable hyper-v).Name | Get-Unique")
	if err != nil {
		return err
	}

	resp := ParseLines(stdout)
	if resp[0] != "Hyper-V" {
		return ErrNotInstalled
	}

	return nil
}

func isAdministrator() (bool, error) {
	hypervAdmin := isHypervAdministrator()

	if hypervAdmin {
		return true, nil
	}

	windowsAdmin, err := IsWindowsAdministrator()

	if err != nil {
		return false, err
	}

	return windowsAdmin, nil
}

func isHypervAdministrator() bool {
	stdout, err := cmdOut(`@([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole("S-1-5-32-578")`)
	if err != nil {
		log.Debug(err)
		return false
	}

	resp := ParseLines(stdout)
	return resp[0] == "True"
}

func IsWindowsAdministrator() (bool, error) {
	stdout, err := cmdOut(`@([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")`)
	if err != nil {
		return false, err
	}

	resp := ParseLines(stdout)
	return resp[0] == "True", nil
}

// This function is used to get the full name of the current user trying to run. It will be DOMAIN\Username or MACHINE_NAME\Username
// TODO - Check if CIFS shares can be used by people who have domain accounts and are local admins on their machines.
func GetCurrentWindowsUser() (string, error) {
	stdout, err := cmdOut(`@([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).Identities.Name`)
	if err != nil {
		return "", err
	}
	response := ParseLines(stdout)
	return response[0], nil
}

func quote(text string) string {
	return fmt.Sprintf("'%s'", text)
}

func toMb(value int) string {
	return fmt.Sprintf("%dMB", value)
}
