package main

import (
	"context"
	"testing"
	"time"
)

func TestChildSetRefusesAfterKillAll(t *testing.T) {
	c := newChildSet()
	killed := 0
	id, err := c.start(func() error { return nil }, func() { killed++ })
	if err != nil {
		t.Fatal(err)
	}
	c.finish(id, nil)
	c.killAll()
	if killed != 0 {
		t.Fatal("a finished child was killed")
	}
	started := false
	if _, err := c.start(func() error { started = true; return nil }, func() {}); err == nil || started {
		t.Fatal("started after killAll")
	}
	r := runCommand(context.Background(), helperSpec("echo", 30*time.Second), c)
	if r.Exit != -1 || r.Why == "" {
		t.Fatalf("runCommand after killAll: %+v", r)
	}
}
