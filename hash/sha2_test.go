package hash

import "testing"

const (
	testDataSHA224Encrypt123456 = "f8cdb04495ded47615258f9dc6a3f4707fd2405434fefc3cbf4ef4e6"
	testDataSHA256Encrypt123456 = "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92"
	testDataSHA384Encrypt123456 = "0a989ebc4a77b56a6e2bb7b19d995d185ce44090c13e2984b7ecc6d446d4b61ea9991b76a4c2f04b1b4d244841449454"
	testDataSHA512Encrypt123456 = "ba3253876aed6bc22d4a6ff53d8406c6ad864195ed144ab5c87621b6c233b548baeae6956df346ec8c17f5ea10f35ee3cbc514797ed7ddd3145464e2a0bab413"
)

func TestSHA224(t *testing.T) {
	if SHA224("123456") != testDataSHA224Encrypt123456 {
		t.Fatalf("SHA224 encrypt failed\n")
	}
}

func TestSHA256(t *testing.T) {
	if SHA256("123456") != testDataSHA256Encrypt123456 {
		t.Fatalf("SHA245 encrypt failed\n")
	}
}

func TestSHA384(t *testing.T) {
	if SHA384("123456") != testDataSHA384Encrypt123456 {
		t.Fatalf("SHA384 encrypt failed\n")
	}
}

func TestSHA512(t *testing.T) {
	if SHA512("123456") != testDataSHA512Encrypt123456 {
		t.Fatalf("SHA512 encrypt failed\n")
	}
}
