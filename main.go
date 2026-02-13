package main

import (
	"archive/tar"
	"compress/gzip"
	"database/sql"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	_ "github.com/glebarez/sqlite"
)

type ALBLog struct {
	Type                   string
	Timestamp              string
	ELB                    string
	ClientIP               string
	ClientPort             int
	TargetIP               string
	TargetPort             int
	RequestProcessingTime  float64
	TargetProcessingTime   float64
	ResponseProcessingTime float64
	ELBStatusCode          int
	TargetStatusCode       int
	ReceivedBytes          int64
	SentBytes              int64
	Request                string
	Method                 string
	Path                   string
	Query                  string
	Protocol               string
	UserAgent              string
	SSLCipher              string
	SSLProtocol            string
	TargetGroupArn         string
	TraceID                string
	DomainName             string
	CertArn                string
	MatchedRulePriority    string
	RequestCreationTime    string
	WafAction              string
	WafResponseCode        string
	WafMatchStatus         string
	TargetPortList         string
	TargetStatusCodeList   string
	ActionsExecuted        string
	RuleName               string
	ConnTraceID            string
}

func main() {
	compressedDir := "compressed"
	dbPath := "cloudfront_logs.db"

	if _, err := os.Stat(compressedDir); os.IsNotExist(err) {
		fmt.Printf("Directory '%s' does not exist\n", compressedDir)
		os.Exit(1)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		fmt.Printf("Failed to open database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	createTable(db)

	gzFiles, err := findGzFiles(compressedDir)
	if err != nil {
		fmt.Printf("Failed to find gz files: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Found %d gz files\n", len(gzFiles))

	totalRecords := 0
	for _, gzPath := range gzFiles {
		records, err := extractAndParseGz(gzPath)
		if err != nil {
			fmt.Printf("Failed to process %s: %v\n", gzPath, err)
			continue
		}

		if err := insertLogs(db, records); err != nil {
			fmt.Printf("Failed to insert logs: %v\n", err)
			continue
		}

		totalRecords += len(records)
		fmt.Printf("Processed %s: %d records\n", filepath.Base(gzPath), len(records))
	}

	fmt.Printf("Total records inserted: %d\n", totalRecords)
	fmt.Printf("Database saved to: %s\n", dbPath)
}

func findGzFiles(dir string) ([]string, error) {
	var gzFiles []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(strings.ToLower(info.Name()), ".gz") {
			gzFiles = append(gzFiles, path)
		}
		return nil
	})
	return gzFiles, err
}

func createTable(db *sql.DB) {
	query := `
	CREATE TABLE IF NOT EXISTS alb_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		type TEXT,
		timestamp TEXT,
		elb TEXT,
		client_ip TEXT,
		client_port INTEGER,
		target_ip TEXT,
		target_port INTEGER,
		request_processing_time REAL,
		target_processing_time REAL,
		response_processing_time REAL,
		elb_status_code INTEGER,
		target_status_code INTEGER,
		received_bytes INTEGER,
		sent_bytes INTEGER,
		request TEXT,
		method TEXT,
		path TEXT,
		query TEXT,
		protocol TEXT,
		user_agent TEXT,
		ssl_cipher TEXT,
		ssl_protocol TEXT,
		target_group_arn TEXT,
		trace_id TEXT,
		domain_name TEXT,
		cert_arn TEXT,
		matched_rule_priority TEXT,
		request_creation_time TEXT,
		waf_action TEXT,
		waf_response_code TEXT,
		waf_match_status TEXT,
		target_port_list TEXT,
		target_status_code_list TEXT,
		actions_executed TEXT,
		rule_name TEXT,
		conn_trace_id TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_timestamp ON alb_logs(timestamp);
	CREATE INDEX IF NOT EXISTS idx_client_ip ON alb_logs(client_ip);
	CREATE INDEX IF NOT EXISTS idx_target_ip ON alb_logs(target_ip);
	CREATE INDEX IF NOT EXISTS idx_elb_status_code ON alb_logs(elb_status_code);
	`
	_, err := db.Exec(query)
	if err != nil {
		fmt.Printf("Failed to create table: %v\n", err)
	}
}

func extractAndParseGz(gzPath string) ([]ALBLog, error) {
	file, err := os.Open(gzPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return nil, err
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)

	header, err := tarReader.Next()
	if err == io.EOF {
		return parseALBLogFile(gzReader)
	}
	if err != nil {
		file.Seek(0, 0)
		gzReader2, err := gzip.NewReader(file)
		if err != nil {
			return nil, err
		}
		defer gzReader2.Close()
		return parseALBLogFile(gzReader2)
	}

	var records []ALBLog

	if header.Typeflag == tar.TypeReg {
		logs, err := parseALBLogFile(tarReader)
		if err != nil {
			fmt.Printf("Warning: error parsing %s: %v\n", header.Name, err)
			return nil, err
		}
		records = append(records, logs...)
	}

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Printf("Warning: error reading tar: %v\n", err)
			continue
		}

		if header.Typeflag == tar.TypeReg {
			logs, err := parseALBLogFile(tarReader)
			if err != nil {
				fmt.Printf("Warning: error parsing %s: %v\n", header.Name, err)
				continue
			}
			records = append(records, logs...)
		}
	}

	return records, nil
}

func parseALBLogFile(reader io.Reader) ([]ALBLog, error) {
	var logs []ALBLog

	buf := make([]byte, 32*1024)
	for {
		n, err := reader.Read(buf)
		if n == 0 {
			break
		}
		if err != nil && err != io.EOF {
			return logs, err
		}

		lines := strings.Split(string(buf[:n]), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			parts := parseALBLogLine(line)
			if len(parts) < 22 {
				continue
			}

			log := ALBLog{
				Type:                   parts[0],
				Timestamp:              parts[1],
				ELB:                    parts[2],
				ClientIP:               extractIP(parts[3]),
				ClientPort:             extractPort(parts[3]),
				TargetIP:               extractIP(parts[4]),
				TargetPort:             extractPort(parts[4]),
				RequestProcessingTime:  parseFloat(parts[5]),
				TargetProcessingTime:   parseFloat(parts[6]),
				ResponseProcessingTime: parseFloat(parts[7]),
				ELBStatusCode:          parseInt(parts[8]),
				TargetStatusCode:       parseInt(parts[9]),
				ReceivedBytes:          parseInt64(parts[10]),
				SentBytes:              parseInt64(parts[11]),
				Request:                parts[12],
				UserAgent:              parts[13],
				SSLCipher:              parts[14],
				SSLProtocol:            parts[15],
				TargetGroupArn:         parts[16],
				TraceID:                parts[17],
				DomainName:             parts[18],
				CertArn:                parts[19],
				MatchedRulePriority:    parts[20],
				RequestCreationTime:    parts[21],
			}

			log.Method, log.Path, log.Query, log.Protocol = parseRequest(parts[12])

			if len(parts) > 22 {
				log.WafAction = parts[22]
			}
			if len(parts) > 23 {
				log.WafResponseCode = parts[23]
			}
			if len(parts) > 24 {
				log.WafMatchStatus = parts[24]
			}
			if len(parts) > 25 {
				log.TargetPortList = parts[25]
			}
			if len(parts) > 26 {
				log.TargetStatusCodeList = parts[26]
			}
			if len(parts) > 27 {
				log.ActionsExecuted = parts[27]
			}
			if len(parts) > 28 {
				log.RuleName = parts[28]
			}
			if len(parts) > 29 {
				log.ConnTraceID = parts[29]
			}

			logs = append(logs, log)
		}
	}

	return logs, nil
}

func parseALBLogLine(line string) []string {
	var parts []string
	var current strings.Builder
	inQuote := false

	for _, c := range line {
		if c == '"' {
			inQuote = !inQuote
			continue
		}
		if c == ' ' && !inQuote {
			parts = append(parts, current.String())
			current.Reset()
			continue
		}
		current.WriteRune(c)
	}
	parts = append(parts, current.String())

	return parts
}

func extractIP(s string) string {
	if idx := strings.Index(s, ":"); idx != -1 {
		return s[:idx]
	}
	return s
}

func extractPort(s string) int {
	if idx := strings.LastIndex(s, ":"); idx != -1 {
		return parseInt(s[idx+1:])
	}
	return 0
}

func insertLogs(db *sql.DB, logs []ALBLog) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO alb_logs (
			type, timestamp, elb, client_ip, client_port, target_ip, target_port,
			request_processing_time, target_processing_time, response_processing_time,
			elb_status_code, target_status_code, received_bytes, sent_bytes,
			request, method, path, query, protocol, user_agent, ssl_cipher, ssl_protocol, target_group_arn,
			trace_id, domain_name, cert_arn, matched_rule_priority, request_creation_time,
			waf_action, waf_response_code, waf_match_status, target_port_list,
			target_status_code_list, actions_executed, rule_name, conn_trace_id
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, log := range logs {
		_, err := stmt.Exec(
			log.Type, log.Timestamp, log.ELB, log.ClientIP, log.ClientPort,
			log.TargetIP, log.TargetPort, log.RequestProcessingTime, log.TargetProcessingTime,
			log.ResponseProcessingTime, log.ELBStatusCode, log.TargetStatusCode,
			log.ReceivedBytes, log.SentBytes, log.Request, log.Method, log.Path, log.Query, log.Protocol, log.UserAgent,
			log.SSLCipher, log.SSLProtocol, log.TargetGroupArn, log.TraceID,
			log.DomainName, log.CertArn, log.MatchedRulePriority, log.RequestCreationTime,
			log.WafAction, log.WafResponseCode, log.WafMatchStatus, log.TargetPortList,
			log.TargetStatusCodeList, log.ActionsExecuted, log.RuleName, log.ConnTraceID,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func parseInt64(s string) int64 {
	if s == "-" || s == "" {
		return 0
	}
	var result int64
	fmt.Sscanf(s, "%d", &result)
	return result
}

func parseInt(s string) int {
	if s == "-" || s == "" {
		return 0
	}
	var result int
	fmt.Sscanf(s, "%d", &result)
	return result
}

func parseFloat(s string) float64 {
	if s == "-" || s == "" {
		return 0
	}
	var result float64
	fmt.Sscanf(s, "%f", &result)
	return result
}

func parseRequest(request string) (method, path, query, protocol string) {
	parts := strings.SplitN(request, " ", 3)
	if len(parts) >= 1 {
		method = parts[0]
	}
	if len(parts) >= 2 {
		parsedURL, err := url.Parse(parts[1])
		if err == nil {
			path = parsedURL.Path
			query = parsedURL.RawQuery
		}
	}
	if len(parts) >= 3 {
		protocol = parts[2]
	}
	return
}
