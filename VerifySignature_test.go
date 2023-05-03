package verifysignature

import (
	"encoding/hex"
	"testing"
)

func TestVerifySignature(t *testing.T) {
	msg, err := hex.DecodeString("269d204413554cf4099df30554c8060ecc5f28302252167e6cc6c563c28dad7f")
	if err != nil {
		panic(err)
	}

	sig, err := hex.DecodeString("304402206BA39DD04FCDDF34CA26F79FDD82E6238A1607BE01EB7F64A53CC83C567E46EE022039265C4D4CA4817FECBB42C943BEF51166C63F640DAD0A555A7A23221A894ECB")
	if err != nil {
		panic(err)
	}

	pubkey, err := hex.DecodeString("0390c85d6d1f222d2780996ca0666c483986e1762fd46be8fe80750285787186fd")
	if err != nil {
		panic(err)
	}

	res := VerifySignature(msg, sig, pubkey)
	t.Log(res)
}
