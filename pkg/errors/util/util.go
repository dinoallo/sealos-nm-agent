package util

import "fmt"

func Err(err error, causedBy error) error {
	if err == nil && causedBy == nil {
		return fmt.Errorf("")
	} else if err != nil && causedBy == nil {
		return fmt.Errorf("%v", err)
	} else if err == nil && causedBy != nil {
		return fmt.Errorf("%v", causedBy)
	} else {
		return fmt.Errorf("%v: %v", err, causedBy)
	}
}
