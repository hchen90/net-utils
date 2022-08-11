// ref: rfc8659
package dns

import (
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

func lookupRecord(msg *dns.Msg, dnss string) (r *dns.Msg, rtt time.Duration, err error) {
	msg.SetEdns0(4096, true)

	cli := &dns.Client{
		Timeout: time.Second * 5,
	}

	r, rtt, err = cli.Exchange(msg, dnss)
	if err != nil {
		logrus.Error(err)
	}
	if r != nil && r.Rcode != dns.RcodeSuccess {
		logrus.Error("lookup record: fatal")
	}
	return
}

func lookupCaaRecord(domain, dnss string) ([]*dns.CAA, time.Duration, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeCAA)
	r, rtt, err := lookupRecord(msg, dnss)
	var result []*dns.CAA
	if r == nil {
		return nil, 0, errors.New("no records")
	}
	for i := range r.Answer {
		if caa, ok := r.Answer[i].(*dns.CAA); ok {
			result = append(result, caa)
		}
	}
	return result, rtt, err
}

func cvtWildDomain(domain string) string {
	if domain[0] == '*' {
		return domain[2:]
	}
	return domain
}

func LookupCAA(domain, dnss string) (result []*dns.CAA, err error) {
	domain = cvtWildDomain(domain) // 通配符筛选

	res, _, er := lookupCaaRecord(domain, dnss)
	if err == nil {
		return res, er
	}

	labels := strings.Split(domain, ".")

	wg := &sync.WaitGroup{}
	cha := make(chan *dns.CAA, 1)

	for i := range labels {
		wg.Add(1)

		go func(domain string) {
			defer wg.Done()

			caas, _, err := lookupCaaRecord(domain, dnss)
			if err != nil {
				logrus.Error(err)
				return
			}
			for i := range caas {
				cha <- caas[i]
			}
		}(strings.Join(labels[i:], "."))
	}

	go func() {
		wg.Wait()
		close(cha)
	}()

	for r := range cha {
		result = append(result, r)
	}

	return
}
