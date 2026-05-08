package portscan

import (
	"reflect"
	"testing"
)

func TestParsePorts(t *testing.T) {
	got, err := ParsePorts("80,443,8080-8082,80")
	if err != nil {
		t.Fatal(err)
	}
	want := []int{80, 443, 8080, 8081, 8082}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ports mismatch: got %v want %v", got, want)
	}
}

func TestParsePortsRejectsInvalid(t *testing.T) {
	if _, err := ParsePorts("0,80"); err == nil {
		t.Fatal("expected invalid port error")
	}
}

func TestParseServicePorts(t *testing.T) {
	got, err := ParseServicePorts("postsql,mysql,redis,rabbitmq,es,web,tomcat,ssh,kafka,ftp,socks,frp,proxy")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []int{21, 22, 80, 443, 1080, 3306, 5432, 6379, 5672, 7000, 7500, 9200, 9092, 8080, 8009, 15672} {
		if !containsPort(got, want) {
			t.Fatalf("service ports missing %d in %v", want, got)
		}
	}
}

func TestParseServicePortsRejectsUnknown(t *testing.T) {
	if _, err := ParseServicePorts("mysql,unknown-service"); err == nil {
		t.Fatal("expected unknown service error")
	}
}

func TestMergePortsSortsAndDeduplicates(t *testing.T) {
	got := MergePorts([]int{443, 80}, []int{80, 22})
	want := []int{22, 80, 443}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ports mismatch: got %v want %v", got, want)
	}
}

func containsPort(ports []int, want int) bool {
	for _, p := range ports {
		if p == want {
			return true
		}
	}
	return false
}
