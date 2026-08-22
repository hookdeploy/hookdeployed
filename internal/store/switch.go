package store

import (
	"bufio"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"
)

const SwitchNeedsTTY = "not a TTY; specify an organization: agent switch <name-or-slug-or-id>"

// RunSwitch implements `agent switch`. No argument on a TTY is a
// numbered picker. No argument without a TTY prints the list and
// returns an error — it never blocks on stdin.
func RunSwitch(root string, args []string, in io.Reader, out io.Writer, tty bool) error {
	orgs, err := List(root)
	if err != nil {
		return err
	}
	if len(orgs) == 0 {
		return fmt.Errorf("no enrolled organizations — run `agent enroll`")
	}

	if len(args) == 0 {
		fmt.Fprint(out, FormatList(orgs))
		if !tty {
			return fmt.Errorf("%s", SwitchNeedsTTY)
		}
		fmt.Fprintf(out, "Select organization [1-%d]: ", len(orgs))
		line, err := bufio.NewReader(in).ReadString('\n')
		if err != nil {
			return fmt.Errorf("switch: read selection: %w", err)
		}
		n, err := strconv.Atoi(strings.TrimSpace(line))
		if err != nil || n < 1 || n > len(orgs) {
			return fmt.Errorf("switch: invalid selection")
		}
		return writeSwitch(root, orgs[n-1], out)
	}

	got, err := Match(orgs, strings.Join(args, " "))
	if err != nil {
		return err
	}
	return writeSwitch(root, got, out)
}

func writeSwitch(root string, got Enrollment, out io.Writer) error {
	if err := WriteActive(root, filepath.Base(got.Dir)); err != nil {
		return err
	}
	label := got.Name
	if strings.TrimSpace(label) == "" {
		label = got.ID
	}
	fmt.Fprintf(out, "active: %s\n", label)
	return nil
}
