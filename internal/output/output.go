// Package output formats and writes scan results to stdout or file.
package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"

	"github.com/yu-929/Vect-IP/internal/engine"
)

// WriteJSONL writes results as JSON Lines format.
func WriteJSONL(w io.Writer, rows []engine.TopResult) error {
	enc := json.NewEncoder(w)
	for _, r := range rows {
		if err := enc.Encode(r); err != nil {
			return err
		}
	}
	return nil
}

// WriteCSV writes results as CSV format.
func WriteCSV(w io.Writer, rows []engine.TopResult) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()

	header := []string{
		"rank", "ip", "prefix",
		"ok", "status",
		"connect_ms", "tls_ms", "ttfb_ms", "total_ms", "jitter_ms",
		"score_ms", "samples_prefix", "ok_prefix", "fail_prefix",
		"download_ok", "download_mbps", "download_peak_mbps", "download_ms", "download_bytes", "download_error",
		"colo",
	}
	if err := cw.Write(header); err != nil {
		return err
	}

	for i, r := range rows {
		colo := ""
		if r.Trace != nil {
			colo = r.Trace["colo"]
		}
		rec := []string{
			strconv.Itoa(i + 1),
			r.IP.String(),
			r.Prefix.String(),
			strconv.FormatBool(r.OK),
			strconv.Itoa(r.Status),
			strconv.FormatInt(r.ConnectMS, 10),
			strconv.FormatInt(r.TLSMS, 10),
			strconv.FormatInt(r.TTFBMS, 10),
			strconv.FormatInt(r.TotalMS, 10),
			fmt.Sprintf("%.2f", r.JitterMS),
			fmt.Sprintf("%.2f", r.ScoreMS),
			strconv.Itoa(r.PrefixSamples),
			strconv.Itoa(r.PrefixOK),
			strconv.Itoa(r.PrefixFail),
			strconv.FormatBool(r.DownloadOK),
			fmt.Sprintf("%.2f", r.DownloadMbps),
			fmt.Sprintf("%.2f", r.DownloadPeakMbps),
			strconv.FormatInt(r.DownloadMS, 10),
			strconv.FormatInt(r.DownloadBytes, 10),
			r.DownloadError,
			colo,
		}
		if err := cw.Write(rec); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// WriteText writes results as human-readable text format.
func WriteText(w io.Writer, rows []engine.TopResult) error {
	// Ensure stable output
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].ScoreMS < rows[j].ScoreMS })
	for i, r := range rows {
		colo := ""
		if r.Trace != nil {
			colo = r.Trace["colo"]
		}
		dl := ""
		if r.DownloadOK || r.DownloadError != "" || r.DownloadMS != 0 || r.DownloadBytes != 0 {
			dl = fmt.Sprintf("\tdl_ok=%v\tdl_mbps=%.2f\tdl_peak=%.2f\tdl_ms=%d", r.DownloadOK, r.DownloadMbps, r.DownloadPeakMbps, r.DownloadMS)
			if r.DownloadError != "" {
				dl += "\tdl_err=" + r.DownloadError
			}
		}
		jitter := ""
		if r.JitterMS > 0 {
			jitter = fmt.Sprintf("\tjitter=%.1fms", r.JitterMS)
		}
		_, err := fmt.Fprintf(w, "%d\t%s\t%.1fms\tok=%v\tstatus=%d\tprefix=%s\tcolo=%s%s%s\n",
			i+1, r.IP.String(), r.ScoreMS, r.OK, r.Status, r.Prefix.String(), colo, jitter, dl)
		if err != nil {
			return err
		}
	}
	return nil
}
