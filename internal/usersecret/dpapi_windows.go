package usersecret

import (
	"bytes"
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

func Protect(data []byte, encrypt bool) ([]byte, error) {
	return protect(data, encrypt, windows.CRYPTPROTECT_UI_FORBIDDEN)
}

// SealMachine permits decryption under the host's other administrator accounts.
// The caller restricts access to the sealed bytes with a filesystem ACL.
func SealMachine(data []byte) ([]byte, error) {
	return protect(data, true, windows.CRYPTPROTECT_UI_FORBIDDEN|windows.CRYPTPROTECT_LOCAL_MACHINE)
}
func protect(data []byte, encrypt bool, flags uint32) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("需要保护的数据为空")
	}
	in := windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
	var out windows.DataBlob
	var err error
	if encrypt {
		err = windows.CryptProtectData(&in, nil, nil, 0, nil, flags, &out)
	} else {
		err = windows.CryptUnprotectData(&in, nil, nil, 0, nil, flags, &out)
	}
	if err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(out.Data))))
	return bytes.Clone(unsafe.Slice(out.Data, out.Size)), nil
}
