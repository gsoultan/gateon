package middleware

import (
	"strings"
)

func (f *Factory) createCompress(cfg map[string]string) (Middleware, error) {
	compressCfg := CompressConfig{
		MinResponseBodyBytes: parsePositiveInt(cfg["min_response_body_bytes"], 1024),
		ExcludedContentTypes: parseListStrict(cfg["excluded_content_types"]),
		IncludedContentTypes: parseListStrict(cfg["included_content_types"]),
		MaxBufferBytes:       parsePositiveInt(cfg["max_buffer_bytes"], 10*1024*1024),
	}
	return CompressWithConfig(compressCfg), nil
}

func parseListStrict(val string) []string {
	if val == "" {
		return nil
	}
	var out []string
	for _, s := range strings.Split(val, ",") {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}
