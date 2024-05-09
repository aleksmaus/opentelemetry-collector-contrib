// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package auditdprocessor // import "github.com/open-telemetry/opentelemetry-collector-contrib/processor/auditdprocessor/internal/logs"

import (
	"encoding/json"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestAuditMessageFromJournalDBody(t *testing.T) {
	const testJournalDBody = `{"AUDIT_FIELD_ACCT":"root","AUDIT_FIELD_ADDR":"?","AUDIT_FIELD_EXE":"/usr/bin/sudo","AUDIT_FIELD_GRANTORS":"pam_limits,pam_env,pam_env,pam_permit,pam_umask,pam_unix","AUDIT_FIELD_HOSTNAME":"?","AUDIT_FIELD_OP":"PAM:session_open","AUDIT_FIELD_RES":"success","AUDIT_FIELD_TERMINAL":"/dev/pts/0","MESSAGE":"USER_START pid=2914644 uid=1000 auid=1000 ses=3 subj=unconfined msg='op=PAM:session_open grantors=pam_limits,pam_env,pam_env,pam_permit,pam_umask,pam_unix acct=\"root\" exe=\"/usr/bin/sudo\" hostname=? addr=? terminal=/dev/pts/0 res=success'","SYSLOG_FACILITY":"4","SYSLOG_IDENTIFIER":"audit","_AUDIT_ID":"18470","_AUDIT_LOGINUID":"1000","_AUDIT_SESSION":"3","_AUDIT_TYPE":"1105","_AUDIT_TYPE_NAME":"USER_START","_BOOT_ID":"81fa5557e3194653869ee1f76f97b960","_HOSTNAME":"lebuntu","_MACHINE_ID":"cae0e0147d454a80971b0b747c8b62b9","_PID":"2914644","_SELINUX_CONTEXT":"unconfined","_SOURCE_REALTIME_TIMESTAMP":"1715284802612000","_TRANSPORT":"audit","_UID":"1000","__CURSOR":"s=8da3d645e11c47f5b16149cb837bad91;i=c9416;b=81fa5557e3194653869ee1f76f97b960;m=b802362cde;t=6180add593f68;x=ed0a8ba711fa5fdf","__MONOTONIC_TIMESTAMP":"790311087326"}`

	const wantRawMessage = `type=USER_START msg=audit(1715284802.612:18470): pid=2914644 uid=1000 auid=1000 ses=3 subj=unconfined msg='op=PAM:session_open grantors=pam_limits,pam_env,pam_env,pam_permit,pam_umask,pam_unix acct="root" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/0 res=success'`

	var body map[string]interface{}

	err := json.Unmarshal([]byte(testJournalDBody), &body)
	if err != nil {
		t.Fatal(err)
	}

	msg, err := auditMessageFromJournalDBody(body)
	if err != nil {
		t.Fatal(err)
	}

	diff := cmp.Diff(wantRawMessage, msg.RawData)

	if diff != "" {
		t.Fatal(diff)
	}
}
