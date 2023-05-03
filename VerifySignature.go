package verifysignature

/*
#cgo CFLAGS: -I./include
#cgo LDFLAGS: -L./lib -lsecp256k1
#include <stdlib.h>
#include <secp256k1.h>
*/
import "C"

// VerifySignature verifies that the given signature for the given message was signed by the given public key.
func VerifySignature(message []byte, signature []byte, publicKey []byte) bool {
	// Create a secp256k1 context
	ctx := C.secp256k1_context_create(C.SECP256K1_CONTEXT_SIGN | C.SECP256K1_CONTEXT_VERIFY)

	// Allocate memory for the message, signature, and public key
	cMessage := C.CBytes(message)
	defer C.free(cMessage)
	cSignature := C.CBytes(signature)
	defer C.free(cSignature)
	cPublicKey := C.CBytes(publicKey)
	defer C.free(cPublicKey)

	// Create a secp256k1 signature object
	var cSig C.secp256k1_ecdsa_signature
	if C.secp256k1_ecdsa_signature_parse_der(ctx, &cSig, (*C.uchar)(cSignature), C.size_t(len(signature))) != 1 {
		return false
	}

	// Create a secp256k1 public key object
	var cPubKey C.secp256k1_pubkey
	if C.secp256k1_ec_pubkey_parse(ctx, &cPubKey, (*C.uchar)(cPublicKey), C.size_t(len(publicKey))) != 1 {
		return false
	}

	// Verify the signature
	if C.secp256k1_ecdsa_verify(ctx, &cSig, (*C.uchar)(cMessage), &cPubKey) != 1 {
		return false
	}

	return true
}
