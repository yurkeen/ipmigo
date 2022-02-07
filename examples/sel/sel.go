package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/yurkeen/ipmigo"
)

// Print system event logs.
func main() {
	c, err := ipmigo.NewClient(ipmigo.Config{
		Version:       ipmigo.V2_0,
		Address:       os.Getenv("IPMI_HOSTPORT"),
		Username:      os.Getenv("IPMI_USERNAME"),
		Password:      os.Getenv("IPMI_PASSWORD"),
		Timeout:       2 * time.Second,
		Retries:       2,
		CipherSuiteID: 3,
	})
	if err != nil {
		fmt.Println(err)
		return
	}

	if err := c.Open(); err != nil {
		fmt.Println(err)
		return
	}
	defer c.Close()

	// Get total count
	_, total, err := ipmigo.SELGetEntries(c, 0, 0)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Get latest 10 events
	count := 10
	offset := 0
	if total > count {
		offset = total - count
	}
	records, total, err := ipmigo.SELGetEntries(c, offset, count)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Output events
	fmt.Println("total", total)
	for _, r := range records {
		switch s := r.(type) {
		case *ipmigo.SELEventRecord:
			dir := "Asserted"
			if !s.IsAssertionEvent() {
				dir = "Deasserted"
			}
			fmt.Printf("%-4d | %-20s | 0x%02x %-25s | %-10s | %s\n",
				s.RecordID, &s.Timestamp, s.SensorNumber, s.SensorType, dir, s.Description())

		case *ipmigo.SELTimestampedOEMRecord:
			fmt.Printf("%-4d | %-20s | OEM Record 0x%02x | 0x%08x | 0x%s\n",
				s.RecordID, &s.Timestamp, s.RecordType, s.ManufacturerID, hex.EncodeToString(s.OEMDefined))

		case *ipmigo.SELNonTimestampedOEMRecord:
			fmt.Printf("%-4d | 0x%s\n", s.RecordID, hex.EncodeToString(s.OEM))
		}
	}
}
