package inspector

import (
	"fmt"
	docker "github.com/fsouza/go-dockerclient"
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
