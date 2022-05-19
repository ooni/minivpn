//build: +integration
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"

	"github.com/ainghazal/minivpn/extras"
	"github.com/ainghazal/minivpn/vpn"
)

const (
	parseConfig = "extract.sh"
	dockerImage = "ainghazal/openvpn"
	dockerTag   = "latest"
)

var (
	target = "172.17.0.1"
	count  = 3
)

func copyFile(src, dst string) error {
	input, err := ioutil.ReadFile(src)
	if err != nil {
		fmt.Println(err)
		return nil
	}

	dstFile := filepath.Join(dst, src)
	err = ioutil.WriteFile(dstFile, input, 0744)
	if err != nil {
		fmt.Println("Error creating", dstFile)
		return err
	}
	return nil
}

func launchDocker(cipher, auth string) ([]byte, *dockertest.Pool, *dockertest.Resource, error) {
	pool, err := dockertest.NewPool("")
	if err != nil {
		log.Fatalf("Could not connect to docker: %s", err)
	}

	options := &dockertest.RunOptions{
		Repository: dockerImage,
		Tag:        dockerTag,
		PortBindings: map[dc.Port][]dc.PortBinding{
			"1194/udp": []dc.PortBinding{{HostPort: "1194"}},
			"8080/tcp": []dc.PortBinding{{HostPort: "8080"}},
		},
		Env:    []string{"OPENVPN_CIPHER=" + cipher, "OPENVPN_AUTH=" + auth},
		CapAdd: []string{"NET_ADMIN"},
	}
	resource, err := pool.RunWithOptions(options)
	if err != nil {
		log.Fatalf("Could not start resource: %s", err)
	}
	// exponential backoff-retry, because the application in the container might not be ready to accept connections yet
	// the minio client does not do service discovery for you (i.e. it does not check if connection can be established), so we have to use the health check
	var config []byte
	if err := pool.Retry(func() error {
		url := fmt.Sprintf("http://localhost:8080/")
		resp, err := http.Get(url)
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("status code not OK")
		}
		config, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			panic(err)
		}
		fmt.Println("Got OpenVPN client config")
		return nil
	}); err != nil {
		log.Fatalf("Could not connect to docker: %s", err)
	}
	return config, pool, resource, nil
}

func stopContainer(p *dockertest.Pool, res *dockertest.Resource) {
	fmt.Println("Stopping container")
	if err := p.Purge(res); err != nil {
		log.Printf("Could not purge resource: %s\n", err)
	}
}

func TestClientAES256GCM(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}
	tmp := t.TempDir()

	copyFile(parseConfig, tmp)
	os.Chdir(tmp)
	err := os.Chmod(parseConfig, 0700)
	if err != nil {
		log.Fatal(err)
	}

	config, pool, resource, err := launchDocker("AES-256-GCM", "SHA256")

	if err != nil {
		log.Fatal(err)
	}
	// when all test done, time to kill and remove the container
	defer stopContainer(pool, resource)

	cfgFile, err := ioutil.TempFile(tmp, "minivpn-e2e-")
	defer cfgFile.Close()
	if err != nil {
		log.Fatal("Cannot create temporary file", err)
	}
	fmt.Println("Config written to: " + cfgFile.Name())

	if _, err = cfgFile.Write(config); err != nil {
		log.Fatal("Failed to write config to temporary file", err)
	}

	// execute the extract.sh shell script, to process key blocks piecewise
	cmd := exec.Command("./"+parseConfig, cfgFile.Name())
	cmd.Dir = tmp
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Run()

	if err != nil {
		log.Fatal(err)
	}

	c, err := readLines("config")
	fmt.Println("Remote:", c[len(c)-1])
	// can assert that this is a remote line

	// actual test begins
	o, err := vpn.ParseConfigFile(filepath.Join(tmp, "config"))
	if err != nil {
		log.Fatalf("Could not parse file: %s", err)
	}
	vpnDialer := vpn.NewVPNDialer(o)
	pinger := extras.NewPinger(vpnDialer, target, count)
	err = pinger.Run()
	defer pinger.Stop()
	if err != nil {
		log.Fatalf("VPN Error: %s", err)
	}
	// let's assert something wise about the pings
	// can we parse the logs? get initialization etc
}

func readLines(f string) ([]string, error) {
	var ll []string
	rf, err := os.Open(f)
	defer rf.Close()
	if err != nil {
		return ll, err
	}
	fs := bufio.NewScanner(rf)
	fs.Split(bufio.ScanLines)
	for fs.Scan() {
		ll = append(ll, fs.Text())
	}
	return ll, nil
}
