// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package auditdprocessor

import (
	"fmt"
	"testing"

	"github.com/elastic/go-libaudit/v2/auparse"
	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func TestFoo(t *testing.T) {
	msg := `type=USER_AUTH msg=audit(1710208209.407:3275): pid=2464874 uid=1000 auid=1000 ses=3 subj=unconfined msg='op=PAM:authentication grantors=pam_permit,pam_cap acct="amaus" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/2 res=success'UID="amaus" AUID="amaus"`
	auditMsg, err := auparse.ParseLogLine(msg)
	if err != nil {
		t.Fatal(err)
	}
	m := auditMsg.ToMapStr()
	fmt.Println("erer")
	_ = auditMsg
	_ = m
}
