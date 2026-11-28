package capture

import (
	"errors"
	"fmt"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Machine-scope DPAPI relies on this ACL to keep ordinary host users from
// reading the encrypted key. ProgramData itself permits users to create folders.
const hostCAPermissions = "O:BAD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)"

func hostCADirectory() (string, error) {
	root, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		return "", err
	}
	dir := filepath.Join(root, "GuestGate-CA")
	if err = ensureCADirectory(dir, hostCAPermissions); err != nil {
		return "", fmt.Errorf("无法打开宿主机 CA 私钥目录 %s：%w", dir, err)
	}
	return dir, nil
}

func ensureCADirectory(path, sddl string) error {
	expected, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	sa := windows.SecurityAttributes{SecurityDescriptor: expected}
	sa.Length = uint32(unsafe.Sizeof(sa))
	if err = windows.CreateDirectory(name, &sa); err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return err
	}
	// Inspect the directory itself, including when another process created it.
	handle, err := windows.CreateFile(name, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	var info windows.ByHandleFileInformation
	if err = windows.GetFileInformationByHandle(handle, &info); err != nil {
		return err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("需要普通目录")
	}
	actual, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	if actual.String() != expected.String() {
		return errors.New("CA 私钥目录的所有者或访问权限不符合要求")
	}
	return nil
}
