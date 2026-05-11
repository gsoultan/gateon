//go:build wasip1

package wasm

import (
	"unsafe"
)

//go:wasmimport env set_header
func hostSetHeader(namePtr, nameLen, valPtr, valLen uint32)

//go:wasmimport env get_header
func hostGetHeader(namePtr, nameLen, valPtr, valLen uint32) uint32

//go:wasmimport env log
func hostLog(msgPtr, msgLen uint32)

//go:wasmimport env get_method
func hostGetMethod(valPtr, valLen uint32) uint32

//go:wasmimport env get_url
func hostGetURL(valPtr, valLen uint32) uint32

//go:wasmimport env record_threat
func hostRecordThreat(typePtr, typeLen, detailsPtr, detailsLen uint32, score float64)

// SetHeader sets a request header.
func SetHeader(name, value string) {
	nPtr, nLen := stringToPtr(name)
	vPtr, vLen := stringToPtr(value)
	hostSetHeader(nPtr, nLen, vPtr, vLen)
}

// GetHeader gets a request header.
func GetHeader(name string) string {
	nPtr, nLen := stringToPtr(name)
	buf := make([]byte, 1024)
	ptr := uint32(uintptr(unsafe.Pointer(unsafe.SliceData(buf))))
	vLen := hostGetHeader(nPtr, nLen, ptr, uint32(len(buf)))
	if vLen > uint32(len(buf)) {
		buf = make([]byte, vLen)
		ptr = uint32(uintptr(unsafe.Pointer(unsafe.SliceData(buf))))
		hostGetHeader(nPtr, nLen, ptr, vLen)
	}
	return string(buf[:vLen])
}

// Log sends a log message to the Gateon logger.
func Log(msg string) {
	ptr, len := stringToPtr(msg)
	hostLog(ptr, len)
}

// GetMethod returns the request method.
func GetMethod() string {
	buf := make([]byte, 16)
	ptr := uint32(uintptr(unsafe.Pointer(unsafe.SliceData(buf))))
	vLen := hostGetMethod(ptr, uint32(len(buf)))
	if vLen > uint32(len(buf)) {
		buf = make([]byte, vLen)
		ptr = uint32(uintptr(unsafe.Pointer(unsafe.SliceData(buf))))
		hostGetMethod(ptr, vLen)
	}
	return string(buf[:vLen])
}

// GetURL returns the request URL.
func GetURL() string {
	buf := make([]byte, 256)
	ptr := uint32(uintptr(unsafe.Pointer(unsafe.SliceData(buf))))
	vLen := hostGetURL(ptr, uint32(len(buf)))
	if vLen > uint32(len(buf)) {
		buf = make([]byte, vLen)
		ptr = uint32(uintptr(unsafe.Pointer(unsafe.SliceData(buf))))
		hostGetURL(ptr, vLen)
	}
	return string(buf[:vLen])
}

// RecordThreat reports a security threat to Gateon.
func RecordThreat(threatType, details string, score float64) {
	tPtr, tLen := stringToPtr(threatType)
	dPtr, dLen := stringToPtr(details)
	hostRecordThreat(tPtr, tLen, dPtr, dLen, score)
}

func stringToPtr(s string) (uint32, uint32) {
	if s == "" {
		return 0, 0
	}
	ptr := unsafe.Pointer(unsafe.StringData(s))
	return uint32(uintptr(ptr)), uint32(len(s))
}
