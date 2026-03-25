// Package crypt handles age encryption and decryption of data streams.
package crypt

import (
	"io"

	"filippo.io/age"
)

// Encrypt encrypts src to dst for the given recipients using age.
func Encrypt(dst io.Writer, src io.Reader, recipients []age.Recipient) error {
	w, err := age.Encrypt(dst, recipients...)
	if err != nil {
		return err
	}
	if _, err := io.Copy(w, src); err != nil {
		return err
	}
	return w.Close()
}

// Decrypt decrypts src to dst using the given identities.
func Decrypt(dst io.Writer, src io.Reader, identities []age.Identity) error {
	r, err := age.Decrypt(src, identities...)
	if err != nil {
		return err
	}
	_, err = io.Copy(dst, r)
	return err
}
