package emailverifier

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDomainToASCII(t *testing.T) {
	domain := "testingΣ✪✯☭➳卐.org"
	ret := DomainToASCII(domain)
	expected := "xn--testing-0if2960fjccubz8h9z13a.org"
	assert.Equal(t, expected, ret)
}

func TestDomainToASCII_NormalDomain(t *testing.T) {
	domain := "testing.org"
	ret := DomainToASCII(domain)
	expected := "testing.org"
	assert.Equal(t, expected, ret)
}

func TestCallJobFuncWithParams_NoOutput(t *testing.T) {
	f := func(a string) { fmt.Println(a) }
	ret := callJobFuncWithParams(f, []interface{}{"testing"})
	assert.Nil(t, ret)
}

func TestCallJobFuncWithParams_WithOutput(t *testing.T) {
	f := func(a int) int { return a * (1 + a) }
	ret := callJobFuncWithParams(f, []interface{}{2})
	assert.Equal(t, int64(6), ret[0].Int())
}

func TestCallJobFuncForgetParams(t *testing.T) {
	f := func(a int) int { return a * (1 + a) }
	ret := callJobFuncWithParams(f, nil)
	assert.Nil(t, ret)
}

func TestCallJobFuncWithWrongFunc(t *testing.T) {
	f := 3
	ret := callJobFuncWithParams(f, nil)
	assert.Nil(t, ret)
}

func TestSplitDomainNoSLD(t *testing.T) {
	domain := "com"
	sld, tld := splitDomain(domain)
	assert.Equal(t, sld, "")
	assert.Equal(t, tld, domain)
}

func TestSplitDomainOK(t *testing.T) {
	domain := "aftership.com"
	sld, tld := splitDomain(domain)
	assert.Equal(t, sld, "aftership")
	assert.Equal(t, tld, "com")
}

func TestSplitDomainNilString(t *testing.T) {
	domain := ""
	sld, tld := splitDomain(domain)
	assert.Equal(t, sld, "")
	assert.Equal(t, tld, "")
}

func TestSplitDomainSubDomain(t *testing.T) {
	domain := "develop.aftership.com"
	sld, tld := splitDomain(domain)
	assert.Equal(t, sld, "aftership")
	assert.Equal(t, tld, "com")
}
