package huudis

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
)

func ecdsaPub(xBytes, yBytes []byte) (*ecdsa.PublicKey, error) {
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     bytesToBigInt(xBytes),
		Y:     bytesToBigInt(yBytes),
	}, nil
}

func rsaPub(nBytes, eBytes []byte) (*rsa.PublicKey, error) {
	// E arrives big-endian, unsigned; shrink to int.
	var e int
	for _, b := range eBytes {
		e = (e << 8) | int(b)
	}
	return &rsa.PublicKey{
		N: bytesToBigInt(nBytes),
		E: e,
	}, nil
}
