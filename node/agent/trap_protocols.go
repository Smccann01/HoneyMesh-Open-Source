package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"time"
)

func handleTCPTrap(port string, t *TrapState, conn net.Conn) {
	switch port {
	case "21":
		handleFTP(t, conn)
	case "22":
		handleSSH(t, conn)
	case "23":
		handleTelnet(t, conn)
	case "25":
		handleSMTP(t, conn)
	case "80", "8080", "443", "9200":
		handleHTTP(port, t, conn)
	case "110":
		handlePOP3(t, conn)
	case "143":
		handleIMAP(t, conn)
	case "445":
		handleSMB(t, conn)
	case "3306":
		handleMySQL(t, conn)
	case "3389":
		handleRDP(t, conn)
	case "5432":
		handlePostgres(t, conn)
	case "6379":
		handleRedis(t, conn)
	default:
		handleGeneric(t, conn)
	}
}

func handleUDPTrap(port string, t *TrapState, pc net.PacketConn, addr net.Addr, payload []byte) {
	switch port {
	case "53":
		if resp := buildDNSRefused(payload); len(resp) > 0 {
			_, _ = pc.WriteTo(resp, addr)
			return
		}
	}
	if t.Banner != "" {
		_, _ = pc.WriteTo([]byte(t.Banner), addr)
	}
}

func handleGeneric(t *TrapState, conn net.Conn) {
	writeBannerIfSet(t, conn)
	sleepTarpit(t)
}

func handleSSH(t *TrapState, conn net.Conn) {
	banner := t.Banner
	if banner == "" {
		banner = "SSH-2.0-OpenSSH_8.4\r\n"
	}
	_, _ = conn.Write([]byte(banner))
	sleepTarpit(t)
}

func handleTelnet(t *TrapState, conn net.Conn) {
	_, _ = conn.Write([]byte("login: "))
	_ = readLineWithTimeout(conn, 10*time.Second)
	_, _ = conn.Write([]byte("Password: "))
	_ = readLineWithTimeout(conn, 10*time.Second)
	_, _ = conn.Write([]byte("\r\nLogin incorrect\r\n"))
	sleepTarpit(t)
}

func handleFTP(t *TrapState, conn net.Conn) {
	greet := t.Banner
	if greet == "" {
		greet = "220 FTP Service Ready\r\n"
	}
	_, _ = conn.Write([]byte(greet))
	sc := bufio.NewScanner(conn)
	for i := 0; i < 20 && sc.Scan(); i++ {
		line := strings.TrimSpace(sc.Text())
		cmd := strings.ToUpper(firstToken(line))
		switch cmd {
		case "USER":
			writeLine(conn, "331 Password required")
		case "PASS":
			writeLine(conn, "230 Login successful")
		case "SYST":
			writeLine(conn, "215 UNIX Type: L8")
		case "FEAT":
			writeLine(conn, "211-Features")
			writeLine(conn, " SIZE")
			writeLine(conn, " UTF8")
			writeLine(conn, "211 End")
		case "PWD":
			writeLine(conn, "257 \"/\" is current directory")
		case "TYPE":
			writeLine(conn, "200 Type set")
		case "PASV":
			writeLine(conn, "227 Entering Passive Mode (127,0,0,1,195,80)")
		case "LIST":
			writeLine(conn, "150 Opening ASCII mode data connection")
			writeLine(conn, "226 Transfer complete")
		case "QUIT":
			writeLine(conn, "221 Goodbye")
			return
		default:
			writeLine(conn, "502 Command not implemented")
		}
	}
}

func handleSMTP(t *TrapState, conn net.Conn) {
	greet := t.Banner
	if greet == "" {
		greet = "220 mail.example.com ESMTP Postfix\r\n"
	}
	_, _ = conn.Write([]byte(greet))
	r := bufio.NewReader(conn)
	for i := 0; i < 30; i++ {
		line, err := readLine(r)
		if err != nil {
			return
		}
		cmd := strings.ToUpper(firstToken(line))
		switch cmd {
		case "EHLO", "HELO":
			writeLine(conn, "250-mail.example.com")
			writeLine(conn, "250-PIPELINING")
			writeLine(conn, "250-SIZE 10240000")
			writeLine(conn, "250-8BITMIME")
			writeLine(conn, "250 HELP")
		case "MAIL":
			writeLine(conn, "250 2.1.0 Ok")
		case "RCPT":
			writeLine(conn, "250 2.1.5 Ok")
		case "DATA":
			writeLine(conn, "354 End data with <CR><LF>.<CR><LF>")
			for {
				l, err := readLine(r)
				if err != nil {
					return
				}
				if l == "." {
					break
				}
			}
			writeLine(conn, "250 2.0.0 Ok: queued")
		case "QUIT":
			writeLine(conn, "221 2.0.0 Bye")
			return
		default:
			writeLine(conn, "250 Ok")
		}
	}
}

func handleHTTP(port string, t *TrapState, conn net.Conn) {
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 2048)
	_, _ = conn.Read(buf)
	switch port {
	case "9200":
		writeLine(conn, "HTTP/1.1 401 Unauthorized")
		writeLine(conn, "Content-Type: application/json")
		writeLine(conn, "Content-Length: 74")
		writeLine(conn, "")
		_, _ = conn.Write([]byte("{\"error\":\"missing authentication credentials\",\"status\":401}"))
	default:
		resp := t.Banner
		if resp == "" {
			resp = "HTTP/1.1 400 Bad Request\r\nServer: nginx/1.20.2\r\n\r\n"
		}
		_, _ = conn.Write([]byte(resp))
	}
}

func handlePOP3(t *TrapState, conn net.Conn) {
	greet := t.Banner
	if greet == "" {
		greet = "+OK POP3 server ready\r\n"
	}
	_, _ = conn.Write([]byte(greet))
	sc := bufio.NewScanner(conn)
	for i := 0; i < 20 && sc.Scan(); i++ {
		cmd := strings.ToUpper(firstToken(sc.Text()))
		switch cmd {
		case "USER":
			writeLine(conn, "+OK")
		case "PASS":
			writeLine(conn, "+OK")
		case "STAT":
			writeLine(conn, "+OK 0 0")
		case "LIST":
			writeLine(conn, "+OK")
			writeLine(conn, ".")
		case "QUIT":
			writeLine(conn, "+OK Bye")
			return
		default:
			writeLine(conn, "-ERR")
		}
	}
}

func handleIMAP(t *TrapState, conn net.Conn) {
	greet := t.Banner
	if greet == "" {
		greet = "* OK IMAP4rev1 Service Ready\r\n"
	}
	_, _ = conn.Write([]byte(greet))
	r := bufio.NewReader(conn)
	for i := 0; i < 30; i++ {
		line, err := readLine(r)
		if err != nil {
			return
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		tag := parts[0]
		cmd := strings.ToUpper(parts[1])
		switch cmd {
		case "CAPABILITY":
			writeLine(conn, "* CAPABILITY IMAP4rev1 IDLE AUTH=PLAIN")
			writeLine(conn, tag+" OK CAPABILITY completed")
		case "LOGIN":
			writeLine(conn, tag+" OK LOGIN completed")
		case "NOOP":
			writeLine(conn, tag+" OK NOOP completed")
		case "LOGOUT":
			writeLine(conn, "* BYE Logging out")
			writeLine(conn, tag+" OK LOGOUT completed")
			return
		default:
			writeLine(conn, tag+" BAD unknown command")
		}
	}
}

func handleRedis(t *TrapState, conn net.Conn) {
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	b := make([]byte, 2048)
	n, _ := conn.Read(b)
	s := strings.ToUpper(string(b[:n]))
	if strings.Contains(s, "PING") {
		_, _ = conn.Write([]byte("+PONG\r\n"))
		return
	}
	_, _ = conn.Write([]byte("-ERR unknown command\r\n"))
}

func handleMySQL(t *TrapState, conn net.Conn) {
	handshake := buildMySQLHandshake()
	_, _ = conn.Write(handshake)

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _ = conn.Read(make([]byte, 256))

	errPkt := buildMySQLError(1045, "28000", "Access denied for user")
	_, _ = conn.Write(errPkt)
}

func handlePostgres(t *TrapState, conn net.Conn) {
	msg := buildPostgresError("FATAL", "3D000", "no pg_hba.conf entry")
	_, _ = conn.Write(msg)
}

func handleSMB(t *TrapState, conn net.Conn) {
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, _ = conn.Read(make([]byte, 512))
	_ = conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
	_, _ = conn.Write([]byte{0x00})
}

func handleRDP(t *TrapState, conn net.Conn) {
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, _ = conn.Read(make([]byte, 512))
	_ = conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
	_, _ = conn.Write([]byte{0x03, 0x00, 0x00, 0x0b, 0x06, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00})
}

func writeBannerIfSet(t *TrapState, conn net.Conn) {
	if t.Banner != "" {
		_, _ = conn.Write([]byte(t.Banner))
	}
}

func sleepTarpit(t *TrapState) {
	if !t.Tarpit {
		return
	}
	d := 10 * time.Second
	if t.TarpitDelay != "" {
		if parsed, err := time.ParseDuration(t.TarpitDelay); err == nil {
			d = parsed
		}
	}
	time.Sleep(d)
}

func readLineWithTimeout(conn net.Conn, d time.Duration) string {
	_ = conn.SetReadDeadline(time.Now().Add(d))
	r := bufio.NewReader(conn)
	line, _ := readLine(r)
	return line
}

func readLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func writeLine(conn net.Conn, s string) {
	if !strings.HasSuffix(s, "\r\n") {
		s += "\r\n"
	}
	_, _ = conn.Write([]byte(s))
}

func firstToken(s string) string {
	parts := strings.Fields(s)
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}

func buildMySQLHandshake() []byte {
	var payload bytes.Buffer
	payload.WriteByte(0x0a)
	payload.WriteString("5.7.38-log")
	payload.WriteByte(0x00)
	_ = binary.Write(&payload, binary.LittleEndian, uint32(1))
	seed1 := make([]byte, 8)
	_, _ = rand.Read(seed1)
	payload.Write(seed1)
	payload.WriteByte(0x00)
	capLower := uint16(0xffff)
	_ = binary.Write(&payload, binary.LittleEndian, capLower)
	payload.WriteByte(0x21)
	_ = binary.Write(&payload, binary.LittleEndian, uint16(0x0002))
	capUpper := uint16(0xffff)
	_ = binary.Write(&payload, binary.LittleEndian, capUpper)
	payload.WriteByte(21)
	payload.Write(make([]byte, 10))
	seed2 := make([]byte, 12)
	_, _ = rand.Read(seed2)
	payload.Write(seed2)
	payload.WriteByte(0x00)
	payload.WriteString("mysql_native_password")
	payload.WriteByte(0x00)

	pl := payload.Bytes()
	header := []byte{byte(len(pl)), byte(len(pl) >> 8), byte(len(pl) >> 16), 0x00}
	return append(header, pl...)
}

func buildMySQLError(code uint16, sqlState string, msg string) []byte {
	var payload bytes.Buffer
	payload.WriteByte(0xff)
	_ = binary.Write(&payload, binary.LittleEndian, code)
	payload.WriteByte('#')
	payload.WriteString(sqlState)
	payload.WriteString(msg)

	pl := payload.Bytes()
	header := make([]byte, 4)
	header[0] = byte(len(pl))
	header[1] = byte(len(pl) >> 8)
	header[2] = byte(len(pl) >> 16)
	header[3] = 2
	return append(header, pl...)
}

func buildPostgresError(severity, code, msg string) []byte {
	var payload bytes.Buffer
	payload.WriteByte('S')
	payload.WriteString(severity)
	payload.WriteByte(0)
	payload.WriteByte('C')
	payload.WriteString(code)
	payload.WriteByte(0)
	payload.WriteByte('M')
	payload.WriteString(msg)
	payload.WriteByte(0)
	payload.WriteByte(0)

	pl := payload.Bytes()
	totalLen := int32(len(pl) + 4)
	var out bytes.Buffer
	out.WriteByte('E')
	_ = binary.Write(&out, binary.BigEndian, totalLen)
	out.Write(pl)
	return out.Bytes()
}

func buildDNSRefused(req []byte) []byte {
	if len(req) < 12 {
		return nil
	}
	id := binary.BigEndian.Uint16(req[0:2])
	flags := binary.BigEndian.Uint16(req[2:4])
	qd := binary.BigEndian.Uint16(req[4:6])

	// find end of question
	i := 12
	for i < len(req) && req[i] != 0 {
		i += int(req[i]) + 1
	}
	if i+5 > len(req) {
		return nil
	}
	i++ // null label
	i += 4
	question := req[12:i]

	flags |= 0x8000
	flags &^= 0x000F
	flags |= 0x0005
	flags |= 0x0080

	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.BigEndian, id)
	_ = binary.Write(&buf, binary.BigEndian, flags)
	_ = binary.Write(&buf, binary.BigEndian, qd)
	_ = binary.Write(&buf, binary.BigEndian, uint16(0))
	_ = binary.Write(&buf, binary.BigEndian, uint16(0))
	_ = binary.Write(&buf, binary.BigEndian, uint16(0))
	buf.Write(question)
	return buf.Bytes()
}
