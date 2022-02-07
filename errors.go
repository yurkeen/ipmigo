package ipmigo

import (
	"fmt"
)

// A CommandError suggests that command execution has failed
type CommandError struct {
	CompletionCode CompletionCode
	Command        Command
}

func (e *CommandError) Error() string {
	return fmt.Sprintf("cOmmand %s (0x%02x) failed - %s", e.Command.Name(), e.Command.Code(), e.CompletionCode)
}
