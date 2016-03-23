package openscap

import (
	"fmt"
	docker "github.com/fsouza/go-dockerclient"
	"strings"
	"testing"
)

func noRHELDist() (int, error) {
	return 0, fmt.Errorf("could not find RHEL dist")
}

func rhel7Dist() (int, error) {
	return 7, nil
}

func noInputCVE(int) (string, error) {
	return "", fmt.Errorf("No Input CVE")
}
func inputCVEMock(int) (string, error) {
	return "cve_file", nil
}

func unableToChroot(...string) ([]byte, error) {
	return []byte(""), fmt.Errorf("can't chroot")
}

func okChrootOscap(...string) ([]byte, error) {
	return []byte(""), nil
}

func rhel3OscapChroot(args ...string) ([]byte, error) {
	return []byte("oval:org.open-scap.cpe.rhel:def:3: true"), nil
}

func rhel7OscapChroot(args ...string) ([]byte, error) {
	if strings.Contains(args[3], "7") {
		return []byte("oval:org.open-scap.cpe.rhel:def:7: true"), nil
	}
	return []byte(""), nil
}

func TestGetRhelDist(t *testing.T) {

	tsRhel7ItIs := &defaultOSCAPScanner{chrootOscap: rhel7OscapChroot}
	tsRhel3Always := &defaultOSCAPScanner{chrootOscap: rhel3OscapChroot}
	noDistErr := fmt.Errorf("could not find RHEL dist")
	tsCantChroot := &defaultOSCAPScanner{chrootOscap: unableToChroot}
	_, cantChrootErr := unableToChroot()

	tests := map[string]struct {
		ts            *defaultOSCAPScanner
		shouldFail    bool
		expectedError error
		expectedDist  int
	}{
		"unable to chroot": {
			ts:            tsCantChroot,
			shouldFail:    true,
			expectedError: cantChrootErr,
		},
		"Always wrong dist": {
			ts:            tsRhel3Always,
			shouldFail:    true,
			expectedError: noDistErr,
		},
		"happy flow": {
			ts:           tsRhel7ItIs,
			shouldFail:   false,
			expectedDist: 7,
		},
	}

	for k, v := range tests {
		dist, err := v.ts.getRHELDist()
		if v.shouldFail && !strings.Contains(err.Error(), v.expectedError.Error()) {
			t.Errorf("%s expected  to cause error:\n%v\nBut got:\n%v", k, v.expectedError, err)
		}
		if !v.shouldFail && err != nil {
			t.Errorf("%s expected to succeed but failed with %v", k, err)
		}
		if !v.shouldFail && dist != v.expectedDist {
			t.Errorf("%s expected to succeed with dist=%d but got %d",
				k, v.expectedDist, dist)
		}
	}
}

func TestScan(t *testing.T) {
	tsNoRhelDist := &defaultOSCAPScanner{rhelDist: noRHELDist}
	_, noRhelDistErr := noRHELDist()

	tsNoInputCVE := &defaultOSCAPScanner{rhelDist: rhel7Dist, inputCVE: noInputCVE}
	_, noInputCVEErr := noInputCVE(0)

	tsCantChroot := &defaultOSCAPScanner{
		rhelDist:    rhel7Dist,
		inputCVE:    inputCVEMock,
		chrootOscap: unableToChroot,
	}
	_, cantChrootErr := unableToChroot()

	tsSuccessMocks := &defaultOSCAPScanner{
		rhelDist:    rhel7Dist,
		inputCVE:    inputCVEMock,
		chrootOscap: okChrootOscap,
	}

	tests := map[string]struct {
		ts            Scanner
		shouldFail    bool
		expectedError error
	}{
		"cant find rhel dist": {
			ts:            tsNoRhelDist,
			shouldFail:    true,
			expectedError: noRhelDistErr,
		},
		"unable to get input cve": {
			ts:            tsNoInputCVE,
			shouldFail:    true,
			expectedError: noInputCVEErr,
		},
		"can't chroot to moutpath": {
			ts:            tsCantChroot,
			shouldFail:    true,
			expectedError: cantChrootErr,
		},
		"happy flow": {
			ts:         tsSuccessMocks,
			shouldFail: false,
		},
	}

	for k, v := range tests {
		err := v.ts.Scan(".", &docker.Image{})
		if v.shouldFail && !strings.Contains(err.Error(), v.expectedError.Error()) {
			t.Errorf("%s expected  to cause error:\n%v\nBut got:\n%v", k, v.expectedError, err)
		}
		if !v.shouldFail && err != nil {
			t.Errorf("%s expected to succeed but failed with %v", k, err)
		}
	}

	for k, v := range map[string]struct {
		mountPath string
		image     *docker.Image
	}{
		"mount path does not exist":     {"nosuchdir", &docker.Image{}},
		"mount path is not a directory": {"openscap.go", &docker.Image{}},
		"image is nil":                  {".", nil},
	} {
		if nil == tsSuccessMocks.Scan(v.mountPath, v.image) {
			t.Errorf("%s did not fail", k)
		}
	}

}
