// Package tags normalises the language tags a request asks for.
package tags

import "golang.org/x/text/language"

// Normalise parses an Accept-Language value into tags.
func Normalise(header string) []language.Tag {
	tags, _, err := language.ParseAcceptLanguage(header)
	if err != nil {
		return nil
	}
	return tags
}

// One parses a single tag.
func One(s string) (language.Tag, error) {
	return language.Parse(s)
}
