package service

import "testing"

func TestProtocolAndProductMapping(t *testing.T) {
	tests := []struct {
		port     int
		protocol string
		service  string
		product  string
	}{
		{22, "ssh", "ssh", "OpenSSH/SSH"},
		{21, "ftp", "ftp", "FTP Server"},
		{3306, "mysql", "mysql", "MySQL"},
		{5432, "postgresql", "postgresql", "PostgreSQL"},
		{6379, "redis", "redis", "Redis"},
		{5672, "amqp", "rabbitmq", "RabbitMQ"},
		{9200, "http", "elasticsearch", "Elasticsearch"},
		{9092, "kafka", "kafka", "Kafka"},
		{1080, "socks", "socks", "SOCKS Proxy"},
		{7500, "http", "frp-dashboard", "frp"},
		{8080, "http", "http", "Web Server"},
	}
	for _, tt := range tests {
		service := guessByPort(tt.port)
		if service != tt.service {
			t.Fatalf("port %d service got %q want %q", tt.port, service, tt.service)
		}
		if protocol := protocolByPort(tt.port); protocol != tt.protocol {
			t.Fatalf("port %d protocol got %q want %q", tt.port, protocol, tt.protocol)
		}
		if product := productByService(service); product != tt.product {
			t.Fatalf("port %d product got %q want %q", tt.port, product, tt.product)
		}
	}
}

func TestVersionFromBanner(t *testing.T) {
	if got := versionFromBanner("ssh", "SSH-2.0-OpenSSH_9.6"); got == "" {
		t.Fatal("expected SSH version")
	}
	if got := versionFromBanner("http", "nginx/1.24.0"); got != "1.24.0" {
		t.Fatalf("unexpected version: %q", got)
	}
}
