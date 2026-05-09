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
	vLen := hostGetHeader(nPtr, nLen, uint32(uintptr(unsafe.Pointer(&buf[0]))), uint32(len(buf)))
	if vLen > uint32(len(buf)) {
		buf = make([]byte, vLen)
		hostGetHeader(nPtr, nLen, uint32(uintptr(unsafe.Pointer(&buf[0]))), vLen)
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
	vLen := hostGetMethod(uint32(uintptr(unsafe.Pointer(&buf[0]))), uint32(len(buf)))
	return string(buf[:vLen])
}

// GetURL returns the request URL.
func GetURL() string {
	buf := make([]byte, 256)
	vLen := hostGetURL(uint32(uintptr(unsafe.Pointer(&buf[0]))), uint32(len(buf)))
	if vLen > uint32(len(buf)) {
		buf = make([]byte, vLen)
		hostGetURL(uint32(uintptr(unsafe.Pointer(&buf[0]))), vLen)
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
