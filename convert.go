package main

import (
	"github.com/sirupsen/logrus"
	"strconv"
)

func Int32arrToStrArr(intArr []int32) []string {
	var strList []string
	for _, i := range intArr {
		strList = append(strList, strconv.FormatInt(int64(i), 10))
	}
	logrus.Debugf("format []int32->[]string correct")
	return strList
}
