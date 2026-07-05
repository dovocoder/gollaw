// Package jsonrpc provides shared JSON-RPC 2.0 protocol handling
// for the MCP and LSP servers.
package jsonrpc

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
)

// Conn is a JSON-RPC 2.0 connection with Content-Length framing.
type Conn struct {
	r       io.Reader
	w       io.Writer
	mu      sync.Mutex
	scanner *bufio.Scanner
}

// NewConn creates a new JSON-RPC connection wrapping r and w.
func NewConn(r io.Reader, w io.Writer) *Conn {
	return &Conn{r: r, w: w}
}

// ReadMessage reads a single JSON-RPC message using Content-Length framing.
func (c *Conn) ReadMessage() ([]byte, error) {
	contentLength := 0
	buf := make([]byte, 1)
	var header strings.Builder

	for {
		_, err := io.ReadFull(c.r, buf)
		if err != nil {
			return nil, err
		}
		ch := buf[0]
		if ch == '\n' {
			line := header.String()
			line = strings.TrimRight(line, "\r")
			header.Reset()
			if line == "" {
				break
			}
			if strings.HasPrefix(line, "Content-Length:") {
				fmt.Sscanf(line, "Content-Length: %d", &contentLength)
			}
			continue
		}
		header.WriteByte(ch)
	}

	if contentLength == 0 {
		return nil, fmt.Errorf("missing Content-Length header")
	}
	data := make([]byte, contentLength)
	_, err := io.ReadFull(c.r, data)
	return data, err
}

// WriteMessage writes a single JSON-RPC message with Content-Length framing.
func (c *Conn) WriteMessage(data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	header := fmt.Sprintf("Content-Length: %d\r\n\r\n", len(data))
	if _, err := c.w.Write([]byte(header)); err != nil {
		return err
	}
	_, err := c.w.Write(data)
	return err
}

// SendResponse sends a JSON-RPC 2.0 success response.
func (c *Conn) SendResponse(id json.RawMessage, result interface{}) {
	resp := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      json.RawMessage(id),
		"result":  result,
	}
	data, _ := json.Marshal(resp)
	c.WriteMessage(data)
}

// SendError sends a JSON-RPC 2.0 error response.
func (c *Conn) SendError(id json.RawMessage, code int, message string) {
	resp := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      json.RawMessage(id),
		"error": map[string]interface{}{
			"code":    code,
			"message": message,
		},
	}
	data, _ := json.Marshal(resp)
	c.WriteMessage(data)
}

// ── (decodeRequest removed — inlined at call sites) ──
