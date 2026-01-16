package krb5writer_test

import (
	"log"
	"os"
	"testing"

	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/krb5test"
	"github.com/murfffi/krb5writer"
	"github.com/stretchr/testify/require"
)

func TestE2E(t *testing.T) {
	l := log.New(os.Stderr, "KDC Test Server: ", log.LstdFlags)
	p := make(map[string][]string)
	p["testuser1"] = []string{"testgroup1"}
	p["HTTP/host.test.realm.com"] = []string{}
	kdc, err := krb5test.NewKDC(p, l)
	require.NoError(t, err)
	kdc.Start()
	defer kdc.Close()
	conf := kdc.KRB5Conf
	t.Logf("%+v", conf)
	krbConfFile := t.TempDir() + "/krb5.conf"
	err = krb5writer.WriteKrb5Conf(conf, krbConfFile)
	require.NoError(t, err)

	loadedConf, err := config.Load(krbConfFile)
	require.NoError(t, err)
	require.Equal(t, conf, loadedConf)
}
