package main

import "strings"

const tunnelTagPrefix = "fanout-"

func tunnelTag(t *Tunnel) string {
	return tunnelTagPrefix + sanitizeTag(t.Node.HostName)
}

func sanitizeTag(name string) string {
	var out strings.Builder
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			out.WriteRune(r)
		default:
			out.WriteByte('-')
		}
	}
	return strings.Trim(out.String(), "-")
}

func exitLabel(t *Tunnel) string {
	region := t.Node.CountryCode
	if region == "" {
		region = t.Node.Country
	}
	suffix := t.Node.HostName
	if t.ExitIP != "" {
		if i := strings.LastIndex(t.ExitIP, "."); i >= 0 {
			suffix = t.ExitIP[i+1:]
		} else {
			suffix = t.ExitIP
		}
	}
	if region == "" {
		return suffix
	}
	return region + "-" + suffix
}

func renameExitSuffix(remark, newLabel string) string {
	if remark == "" {
		return remark
	}
	parts := strings.Split(remark, "-")
	if len(parts) < 2 {
		return remark
	}
	keep := parts[:len(parts)-2]
	if len(keep) == 0 {
		return newLabel
	}
	return strings.Join(keep, "-") + "-" + newLabel
}
