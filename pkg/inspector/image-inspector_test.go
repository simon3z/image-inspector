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
type SuccWithHTMLMockScanner struct {
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
func (ms *FailMockScanner) HTMLResultsFileName() string {
	return "NoSuchFile"
}

func (ms *SuccWithHTMLMockScanner) HTMLResultsFileName() string {
	return "image-inpector_test.go"
}

func (ms *SuccMockScanner) Scan(string, *docker.Image) error {
	return nil
}

func (ms *NoResMockScanner) ResultsFileName() string {
	return "NoSuchFILE"
}

func TestScanImage(t *testing.T) {
	iiWithHtml := defaultImageInspector{}
	iiWithHtml.opts.OpenScapHTML = true

	for k, v := range map[string]struct {
		ii         defaultImageInspector
		s          openscap.Scanner
		shouldFail bool
	}{
		"Scanner fails on scan":       {ii: defaultImageInspector{}, s: &FailMockScanner{}, shouldFail: true},
		"Results file does not exist": {ii: defaultImageInspector{}, s: &NoResMockScanner{}, shouldFail: true},
		"Happy Flow":                  {ii: defaultImageInspector{}, s: &SuccMockScanner{}, shouldFail: false},
		"can't read html report":      {ii: iiWithHtml, s: &SuccMockScanner{}, shouldFail: true},
		"Happy Flow with html":        {ii: iiWithHtml, s: &SuccWithHTMLMockScanner{}, shouldFail: true},
	} {
		v.ii.opts.DstPath = "here"
		ii := &v.ii
		report, htmlReport, err := ii.scanImage(v.s)
		if v.shouldFail && err == nil {
			t.Errorf("%s should have failed but it didn't!", k)
		}
		if !v.shouldFail {
			if err != nil {
				t.Errorf("%s should have succeeded but failed with %v", k, err)
			} else {
				resultFileContent, err := ioutil.ReadFile(v.s.ResultsFileName())
				if string(resultFileContent) != string(report) {
					t.Errorf("%s returned wrong results", k, err)
				}
				htmlResultFileContent, err := ioutil.ReadFile(v.s.HTMLResultsFileName())
				if string(htmlResultFileContent) != string(htmlReport) {
					t.Errorf("%s returned wrong html results", k, err)
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

	badUserAndPass := iicmd.NewDefaultImageInspectorOptions()
	badUserAndPass.Username = "erez"
	badUserAndPass.PasswordFile = "test/nosuchfile"

	badDockerCfgMissing := iicmd.NewDefaultImageInspectorOptions()
	badDockerCfgMissing.DockerCfg.Values = []string{"test/dockercfg1", "test/nosuchfile"}

	badDockerCfgWrong := iicmd.NewDefaultImageInspectorOptions()
	badDockerCfgWrong.DockerCfg.Values = []string{"test/dockercfg1", "test/passwordFile1"}

	badDockerCfgNoAuth := iicmd.NewDefaultImageInspectorOptions()
	badDockerCfgNoAuth.DockerCfg.Values = []string{"test/dockercfg1", "test/dockercfg3"}

	tests := map[string]struct {
		opts          *iicmd.ImageInspectorOptions
		expectedAuths int
		shouldFail    bool
	}{
		"two dockercfg":               {opts: goodTwoDockerCfg, expectedAuths: 3, shouldFail: false},
		"username and passwordFile":   {opts: goodUserAndPass, expectedAuths: 1, shouldFail: false},
		"two dockercfg, one missing":  {opts: badDockerCfgMissing, expectedAuths: 2, shouldFail: false},
		"two dockercfg, one wrong":    {opts: badDockerCfgWrong, expectedAuths: 2, shouldFail: false},
		"two dockercfg, no auth":      {opts: badDockerCfgNoAuth, expectedAuths: 2, shouldFail: false},
		"password file doens't exist": {opts: badUserAndPass, expectedAuths: 1, shouldFail: true},
		"no auths, default expected":  {opts: goodNoAuth, expectedAuths: 1, shouldFail: false},
	}

	for k, v := range tests {
		ii := &defaultImageInspector{*v.opts, InspectorMetadata{}}
		auths, err := ii.getAuthConfigs()
		if !v.shouldFail {
			if err != nil {
				t.Errorf("%s expected to succeed but received %v", k, err)
			}
			var authsLen int = 0
			if auths != nil {
				authsLen = len(auths.Configs)
			}
			if auths == nil || v.expectedAuths != authsLen {
				t.Errorf("%s expected len to be %d but got %d from %v",
					k, v.expectedAuths, authsLen, auths)
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
