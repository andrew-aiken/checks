package winrm

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/jcmturner/gokrb5/v8/client"
	krbconfig "github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/spnego"
	winrmClient "github.com/masterzen/winrm"
	"github.com/masterzen/winrm/soap"
)

// kerberosTransport authenticates WinRM requests over Kerberos without requiring
// an on-disk krb5.conf file: the KDC and realm are built in-memory from the check
// Definition instead of being parsed from a config file.
type kerberosTransport struct {
	Username string
	Password string
	Realm    string
	KDCHost  string
	Hostname string
	Port     int
	Proto    string
	SPN      string

	transport http.RoundTripper
}

func (k *kerberosTransport) Transport(endpoint *winrmClient.Endpoint) error {
	k.transport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: endpoint.Insecure, // #nosec G402
			ServerName:         endpoint.TLSServerName,
		},
		ResponseHeaderTimeout: endpoint.Timeout,
	}
	return nil
}

func (k *kerberosTransport) Post(_ *winrmClient.Client, request *soap.SoapMessage) (response string, postErr error) {
	cfg := krbconfig.New()
	cfg.LibDefaults.DefaultRealm = k.Realm
	cfg.Realms = []krbconfig.Realm{
		{
			Realm: k.Realm,
			KDC:   []string{fmt.Sprintf("%s:88", k.KDCHost)},
		},
	}

	kerberosClient := client.NewWithPassword(k.Username, k.Realm, k.Password, cfg,
		client.DisablePAFXFAST(true), client.AssumePreAuthentication(true))

	winrmURL := fmt.Sprintf("%s://%s:%d/wsman", k.Proto, k.Hostname, k.Port)

	winRMRequest, err := http.NewRequest("POST", winrmURL, strings.NewReader(request.String()))
	if err != nil {
		postErr = fmt.Errorf("unable to create request: %w", err)
		return
	}
	winRMRequest.Header.Add("Content-Type", "application/soap+xml;charset=UTF-8")

	if err := spnego.SetSPNEGOHeader(kerberosClient, winRMRequest, k.SPN); err != nil {
		postErr = fmt.Errorf("unable to set SPNego Header: %w", err)
		return
	}

	httpClient := &http.Client{Transport: k.transport}
	resp, err := httpClient.Do(winRMRequest)
	if err != nil {
		postErr = err
		return
	}
	defer func() {
		bodyCloseErr := resp.Body.Close()
		if err == nil && bodyCloseErr != nil {
			err = fmt.Errorf("error closing response body: %s", bodyCloseErr.Error())
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		postErr = err
		return
	}

	if resp.StatusCode != 200 {
		postErr = fmt.Errorf("request returned: %d - %s. Response body:\n%s", resp.StatusCode, resp.Status, string(body))
		return
	}

	response = string(body)
	return
}
