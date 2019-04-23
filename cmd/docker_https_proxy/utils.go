package main

import "strings"

// IsTrueValue checks if the string represents a true value.
func IsTrueValue(s string) bool {
	return s == "1" || strings.ToLower(s) == "on"
}
