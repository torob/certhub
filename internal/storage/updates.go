package storage

import "time"

type OptionalString struct {
	Set   bool
	Value *string
}

func SetString(value string) OptionalString {
	return OptionalString{Set: true, Value: &value}
}

func ClearString() OptionalString {
	return OptionalString{Set: true}
}

type OptionalBool struct {
	Set   bool
	Value bool
}

func SetBool(value bool) OptionalBool {
	return OptionalBool{Set: true, Value: value}
}

type OptionalInt struct {
	Set   bool
	Value int
}

func SetInt(value int) OptionalInt {
	return OptionalInt{Set: true, Value: value}
}

type OptionalTime struct {
	Set   bool
	Value *time.Time
}

func SetTime(value time.Time) OptionalTime {
	return OptionalTime{Set: true, Value: &value}
}

func ClearTime() OptionalTime {
	return OptionalTime{Set: true}
}
