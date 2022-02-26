package main

import (
	"github.com/sirupsen/logrus"
	"testing"
)

func TestInt32arrToStrArr(t *testing.T) {
	logrus.SetLevel(logLevel)
	var a = []string{}
	a = Int32arrToStrArr([]int32{80, 443})
	var b = []string{"80", "443"}
	if Equal(a, b) != true {
		t.Error("Expected 80,443 got", a)
	}
}

func Equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}
