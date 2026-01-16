package template

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/murfffi/gorich/helperr"
)

func WriteKrb5Conf(config *config.Config, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer helperr.CloseQuietly(f)

	// [libdefaults]
	_, err = fmt.Fprintln(f, "[libdefaults]")
	if err != nil {
		return err
	}
	ld := config.LibDefaults
	writeBool(f, "allow_weak_crypto", ld.AllowWeakCrypto, &err)
	writeBool(f, "canonicalize", ld.Canonicalize, &err)
	if ld.CCacheType != 0 {
		writeIndentedLine(f, 1, "ccache_type = %d", &err, ld.CCacheType)
	}
	if ld.Clockskew != 0 {
		writeIndentedLine(f, 1, "clockskew = %s", &err, ld.Clockskew)
	}
	writeString(f, "default_client_keytab_name", ld.DefaultClientKeytabName, &err)
	writeString(f, "default_keytab_name", ld.DefaultKeytabName, &err)
	writeString(f, "default_realm", ld.DefaultRealm, &err)
	writeStringSlice(f, "default_tgs_enctypes", ld.DefaultTGSEnctypes, &err)
	writeStringSlice(f, "default_tkt_enctypes", ld.DefaultTktEnctypes, &err)
	writeBool(f, "dns_canonicalize_hostname", ld.DNSCanonicalizeHostname, &err)
	writeBool(f, "dns_lookup_kdc", ld.DNSLookupKDC, &err)
	writeBool(f, "dns_lookup_realm", ld.DNSLookupRealm, &err)

	if len(ld.ExtraAddresses) > 0 {
		var s []string
		for _, ip := range ld.ExtraAddresses {
			s = append(s, ip.String())
		}
		writeIndentedLine(f, 1, "extra_addresses = %s", &err, strings.Join(s, ","))
	}

	writeBool(f, "forwardable", ld.Forwardable, &err)
	writeBool(f, "ignore_acceptor_hostname", ld.IgnoreAcceptorHostname, &err)
	writeBool(f, "k5login_authoritative", ld.K5LoginAuthoritative, &err)
	writeString(f, "k5login_directory", ld.K5LoginDirectory, &err)

	if len(ld.KDCDefaultOptions.Bytes) > 0 {
		writeIndentedLine(f, 1, "kdc_default_options = 0x%s", &err, hex.EncodeToString(ld.KDCDefaultOptions.Bytes))
	}

	if ld.KDCTimeSync != 0 {
		writeIndentedLine(f, 1, "kdc_timesync = %d", &err, ld.KDCTimeSync)
	}

	writeBool(f, "noaddresses", ld.NoAddresses, &err)
	writeStringSlice(f, "permitted_enctypes", ld.PermittedEnctypes, &err)

	if len(ld.PreferredPreauthTypes) > 0 {
		var s []string
		for _, v := range ld.PreferredPreauthTypes {
			s = append(s, fmt.Sprintf("%d", v))
		}
		writeIndentedLine(f, 1, "preferred_preauth_types = %s", &err, strings.Join(s, ","))
	}

	writeBool(f, "proxiable", ld.Proxiable, &err)
	writeBool(f, "rdns", ld.RDNS, &err)

	// RealmTryDomains default -1.
	if ld.RealmTryDomains != -100 { // Hack: relying on 0 being possibly valid? The parser defaults to -1.
		// If it is -1, do we write it? Yes.
		writeIndentedLine(f, 1, "realm_try_domains = %d", &err, ld.RealmTryDomains)
	}

	if ld.RenewLifetime != 0 {
		writeIndentedLine(f, 1, "renew_lifetime = %s", &err, ld.RenewLifetime)
	}

	if ld.SafeChecksumType != 0 {
		writeIndentedLine(f, 1, "safe_checksum_type = %d", &err, ld.SafeChecksumType)
	}

	if ld.TicketLifetime != 0 {
		writeIndentedLine(f, 1, "ticket_lifetime = %s", &err, ld.TicketLifetime)
	}

	if ld.UDPPreferenceLimit != 1465 { // Default is 1465 in LibDefaults?
		// In newLibDefaults it is 1465.
		// We should probably write it whatever it is.
		writeIndentedLine(f, 1, "udp_preference_limit = %d", &err, ld.UDPPreferenceLimit)
	}
	writeBool(f, "verify_ap_req_nofail", ld.VerifyAPReqNofail, &err)

	if err != nil {
		return err
	}
	// [realms]
	_, err = fmt.Fprintln(f, "\n[realms]")
	if err != nil {
		return err
	}
	for _, r := range config.Realms {
		writeIndentedLine(f, 1, "%s = {", &err, r.Realm)
		for _, v := range r.AdminServer {
			writeIndentedLine(f, 2, "admin_server = %s", &err, v)
		}
		if r.DefaultDomain != "" {
			writeIndentedLine(f, 2, "default_domain = %s", &err, r.DefaultDomain)
		}
		for _, v := range r.KDC {
			writeIndentedLine(f, 2, "kdc = %s", &err, v)
		}
		for _, v := range r.KPasswdServer {
			// Parser defaults kpasswd_server to admin_server:464 if missing.
			// But if it is present, write it.
			writeIndentedLine(f, 2, "kpasswd_server = %s", &err, v)
		}
		for _, v := range r.MasterKDC {
			writeIndentedLine(f, 2, "master_kdc = %s", &err, v)
		}
		writeIndentedLine(f, 1, "}", &err)
	}

	if err != nil {
		return err
	}
	// [domain_realm]
	_, err = fmt.Fprintln(f, "\n[domain_realm]")
	if err != nil {
		return err
	}
	var domains []string
	for d := range config.DomainRealm {
		domains = append(domains, d)
	}
	sort.Strings(domains)
	for _, d := range domains {
		writeIndentedLine(f, 1, "%s = %s", &err, d, config.DomainRealm[d])
	}

	return err
}

func writeIndentedLine(w io.Writer, indent int, format string, outErr *error, a ...any) {
	if *outErr != nil {
		return
	}
	_, err := fmt.Fprintf(w, strings.Repeat("\t", indent)+format+"\n", a...)
	*outErr = err
}

func writeBool(w io.Writer, key string, v bool, outErr *error) {
	writeIndentedLine(w, 1, "%s = %t", outErr, key, v)
}

func writeString(w io.Writer, key string, v string, outErr *error) {
	if v != "" {
		writeIndentedLine(w, 1, "%s = %s", outErr, key, v)
	}
}

func writeStringSlice(w io.Writer, key string, v []string, outErr *error) {
	if len(v) > 0 {
		writeIndentedLine(w, 1, "%s = %s", outErr, key, strings.Join(v, " "))
	}
}
