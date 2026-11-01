package trustclient

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

// AuthCodePrompt reads a 2FA / access code when a user-bound token needs step-up.
// reason is the prompt text from the Gateway (the 401 response body).
type AuthCodePrompt func(reason string) (string, error)

// ConsoleAuthCodePrompt reads a 2FA / access code from stdin.
func ConsoleAuthCodePrompt(reason string) (string, error) {
	return readAuthCode(os.Stdin, os.Stdout, reason)
}

func readAuthCode(in io.Reader, out io.Writer, reason string) (string, error) {
	label := strings.TrimSpace(reason)
	if label == "" {
		label = "authentication code"
	}
	if _, err := fmt.Fprintf(out, "Trust %s: ", label); err != nil {
		return "", err
	}
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && len(line) == 0 {
		return "", err
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return "", fmt.Errorf("empty authentication code")
	}
	return line, nil
}
