package main

import (
	"net/url"
	"regexp"
	"sort"
	"strings"
)

type NormalizeOptions struct {
	IgnoreHash        bool
	NormalizeQuery    string
	StripIndexHTML    bool
	LowercaseHost     bool
	RemoveDefaultPort bool
}

func DefaultNormalizeOptions() NormalizeOptions {
	return NormalizeOptions{
		IgnoreHash:        true,
		NormalizeQuery:    "sort",
		StripIndexHTML:    true,
		LowercaseHost:     true,
		RemoveDefaultPort: true,
	}
}

func ToAbsoluteURL(href, base string) (string, error) {
	if href == "" {
		return "", nil
	}

	baseURL, err := url.Parse(base)
	if err != nil {
		return "", err
	}

	hrefURL, err := url.Parse(href)
	if err != nil {
		return "", err
	}

	absoluteURL := baseURL.ResolveReference(hrefURL)

	if absoluteURL.Scheme != "http" && absoluteURL.Scheme != "https" {
		return "", nil
	}

	return absoluteURL.String(), nil
}

func CanonicalizeURL(href string, opts NormalizeOptions) string {
	u, err := url.Parse(href)
	if err != nil {
		return href
	}

	u.User = nil

	if opts.LowercaseHost {
		u.Host = strings.ToLower(u.Host)
	}

	if opts.RemoveDefaultPort {
		if (u.Scheme == "http" && strings.HasSuffix(u.Host, ":80")) ||
			(u.Scheme == "https" && strings.HasSuffix(u.Host, ":443")) {
			u.Host = strings.TrimSuffix(strings.TrimSuffix(u.Host, ":80"), ":443")
		}
	}

	u.Path = regexp.MustCompile(`/+`).ReplaceAllString(u.Path, "/")

	if !strings.HasPrefix(u.Path, "/") && u.Path != "" {
		u.Path = "/" + u.Path
	}

	if opts.StripIndexHTML {
		indexPattern := regexp.MustCompile(`/index\.(html?|php)$`)
		if indexPattern.MatchString(u.Path) {
			u.Path = indexPattern.ReplaceAllString(u.Path, "/")
		}
	}

	if opts.NormalizeQuery == "sort" && u.RawQuery != "" {
		u.RawQuery = sortQueryParams(u.RawQuery)
	} else if opts.NormalizeQuery == "remove" {
		u.RawQuery = ""
	}

	if opts.IgnoreHash {
		u.Fragment = ""
	}

	return u.String()
}

func sortQueryParams(rawQuery string) string {
	params, err := url.ParseQuery(rawQuery)
	if err != nil {
		return rawQuery
	}

	type kvPair struct {
		key   string
		value string
	}
	var pairs []kvPair

	for key, values := range params {
		for _, value := range values {
			pairs = append(pairs, kvPair{key, value})
		}
	}

	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].key == pairs[j].key {
			return pairs[i].value < pairs[j].value
		}
		return pairs[i].key < pairs[j].key
	})

	newParams := url.Values{}
	for _, p := range pairs {
		newParams.Add(p.key, p.value)
	}

	return newParams.Encode()
}

func IsInScope(href, baseURL, scopePath string) bool {
	u, err := url.Parse(href)
	if err != nil {
		return false
	}

	base, err := url.Parse(baseURL)
	if err != nil {
		return false
	}

	if u.Scheme != base.Scheme || u.Host != base.Host {
		return false
	}

	if scopePath == "" || scopePath == "/" {
		return true
	}

	scopePath = strings.TrimSuffix(scopePath, "/")

	return u.Path == scopePath || strings.HasPrefix(u.Path, scopePath+"/")
}
