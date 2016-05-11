package inspector

import (
	"fmt"
	docker "github.com/fsouza/go-dockerclient"
	iicmd "github.com/openshift/image-inspector/pkg/cmd"
	"github.com/openshift/image-inspector/pkg/openscap"
	"io/ioutil"
	"os"
	"testing"
)

type FailMockScanner struct{}
type SuccMockScanner struct {
	FailMockScanner
}
type NoResMockScanner struct {
	SuccMockScanner
}

func (ms *FailMockScanner) Scan(string, *docker.Image) error {
	return fmt.Errorf("FAIL SCANNER!")
}
func (ms *FailMockScanner) ScannerName() string {
	return "MockScanner"
}
func (ms *FailMockScanner) ResultsFileName() string {
	return "image-inspector_test.go"
}

func (ms *SuccMockScanner) Scan(string, *docker.Image) error {
	return nil
}

func (ms *NoResMockScanner) ResultsFileName() string {
	return "NoSuchFILE"
}

func TestScanImage(t *testing.T) {

	for k, v := range map[string]struct {
		s          openscap.Scanner
		shouldFail bool
	}{
		"Scanner fails on scan":       {s: &FailMockScanner{}, shouldFail: true},
		"Results file does not exist": {s: &NoResMockScanner{}, shouldFail: true},
		"Happy Flow":                  {s: &SuccMockScanner{}, shouldFail: false},
	} {
		ii := defaultImageInspector{}
		ii.opts.DstPath = "here"
		report, err := ii.scanImage(v.s)
		if v.shouldFail && err == nil {
			t.Errorf("%s should have failed but it didn't!", k)
		}
		if !v.shouldFail {
			if err != nil {
				t.Errorf("%s should have succeeded but failed with %v", k, err)
			} else {
				resultFileContent, err := ioutil.ReadFile(v.s.ResultsFileName())
				if string(resultFileContent) != string(report) {
					t.Errorf("%s should have succeeded but failed with %v", k, err)
				}
			}
		}
	}
}

func TestGetAuthConfigs(t *testing.T) {
	goodNoAuth := iicmd.NewDefaultImageInspectorOptions()

	goodTwoDockerCfg := iicmd.NewDefaultImageInspectorOptions()
	goodTwoDockerCfg.DockerCfg.Values = []string{"test/dockercfg1", "test/dockercfg2"}

	goodUserAndPass := iicmd.NewDefaultImageInspectorOptions()
	goodUserAndPass.Username = "erez"
	goodUserAndPass.PasswordFile = "test/passwordFile1"

	badDockerCfgMissing := iicmd.NewDefaultImageInspectorOptions()
	badDockerCfgMissing.DockerCfg.Values = []string{"test/dockercfg1", "test/nosuchfile"}

	badDockerCfgWrong := iicmd.NewDefaultImageInspectorOptions()
	badDockerCfgWrong.DockerCfg.Values = []string{"test/dockercfg1", "test/passwordFile1"}

	badDockerCfgNoAuth := iicmd.NewDefaultImageInspectorOptions()
	badDockerCfgNoAuth.DockerCfg.Values = []string{"test/dockercfg1", "test/dockercfg3"}

	tests := map[string]struct {
		opts       *iicmd.ImageInspectorOptions
		shouldFail bool
	}{
		"two dockercfg":              {opts: goodTwoDockerCfg, shouldFail: false},
		"username and passwordFile":  {opts: goodUserAndPass, shouldFail: false},
		"two dockercfg, one missing": {opts: badDockerCfgMissing, shouldFail: true},
		"two dockercfg, one wrong":   {opts: badDockerCfgWrong, shouldFail: true},
		"two dockercfg, no auth":     {opts: badDockerCfgNoAuth, shouldFail: true},
		"no auths, default expected": {opts: goodNoAuth, shouldFail: false},
	}

	for k, v := range tests {
		ii := &defaultImageInspector{*v.opts, InspectorMetadata{}}
		auths, err := ii.getAuthConfigs()
		if !v.shouldFail {
			var expectedLength int = len(v.opts.DockerCfg.Values) + 1
			if len(v.opts.Username) > 0 {
				expectedLength = 1
			}
			if err != nil {
				t.Errorf("%s expected to succeed but received %v", k, err)
			}
			var authsLen int = 0
			if auths != nil {
				authsLen = len(auths.Configs)
			}
			if auths == nil || expectedLength != authsLen {
				t.Errorf("%s expected len to be %d but got %d from %v",
					k, expectedLength, authsLen, auths)
			}
		} else {
			if err == nil {
				t.Errorf("%s should have failed be it didn't", k)
			}
		}
	}
}

func mkSucc(string, os.FileMode) error {
	return nil
}

func mkFail(string, os.FileMode) error {
	return fmt.Errorf("MKFAIL")
}

func tempSucc(string, string) (string, error) {
	return "tempname", nil
}

func tempFail(string, string) (string, error) {
	return "", fmt.Errorf("TEMPFAIL!")
}

func TestCreateOutputDir(t *testing.T) {
	oldMkdir := osMkdir
	defer func() { osMkdir = oldMkdir }()

	oldTempdir := ioutil.TempDir
	defer func() { ioutilTempDir = oldTempdir }()

	for k, v := range map[string]struct {
		dirName    string
		shouldFail bool
		newMkdir   func(string, os.FileMode) error
		newTempDir func(string, string) (string, error)
	}{
		"good existing dir": {dirName: "/tmp", shouldFail: false, newMkdir: mkSucc},
		"good new dir":      {dirName: "delete_me", shouldFail: false, newMkdir: mkSucc},
		"good temporary":    {dirName: "", shouldFail: false, newMkdir: mkSucc, newTempDir: tempSucc},
		"cant create temp":  {dirName: "", shouldFail: true, newMkdir: mkSucc, newTempDir: tempFail},
		"mkdir fails":       {dirName: "delete_me", shouldFail: true, newMkdir: mkFail},
	} {
		osMkdir = v.newMkdir
		ioutilTempDir = v.newTempDir
		_, err := createOutputDir(v.dirName, "temp-name-")
		if v.shouldFail {
			if err == nil {
				t.Errorf("%s should have failed but it didn't!", k)
			}
		} else {
			if err != nil {
				t.Errorf("%s should have succeeded but failed with %v", k, err)
			}
		}
	}
}
