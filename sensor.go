package ipmigo

import (
	"fmt"
)

type ThresholdStatus string

const (
	// Normal operating ranges
	ThresholdStatusOK ThresholdStatus = "ok"
	// Lower Non-Recoverable
	ThresholdStatusLNR ThresholdStatus = "lnr"
	// Lower Critical
	ThresholdStatusLCR ThresholdStatus = "lcr"
	// Lower Non-Critical
	ThresholdStatusLNC ThresholdStatus = "lnc"
	// Upper Non-Recoverable
	ThresholdStatusUNR ThresholdStatus = "unr"
	// Upper Critical
	ThresholdStatusUCR ThresholdStatus = "ucr"
	// Upper Non-Critical
	ThresholdStatusUNC ThresholdStatus = "unc"
)

// Returns threshold status of threshold-base sensor.
func NewThresholdStatus(status uint8) ThresholdStatus {
	if status&0x04 != 0 {
		return ThresholdStatusLNR
	}
	if status&0x20 != 0 {
		return ThresholdStatusUNR
	}
	if status&0x02 != 0 {
		return ThresholdStatusLCR
	}
	if status&0x10 != 0 {
		return ThresholdStatusUCR
	}
	if status&0x01 != 0 {
		return ThresholdStatusLNC
	}
	if status&0x08 != 0 {
		return ThresholdStatusUNC
	}
	return ThresholdStatusOK
}

// Sensor Type (Table 42-3)
type SensorType uint8

func (t SensorType) String() string {
	sensorType := []string{
		"reserved",                    // 00h
		"Temperature",                 // 01h
		"Voltage",                     // 02h
		"Current",                     // 03h
		"Fan",                         // 04h
		"Physical Security",           // 05h
		"Platform Security",           // 06h
		"Processor",                   // 07h
		"Power Supply",                // 08h
		"Power Unit",                  // 09h
		"Cooling Device",              // 0Ah
		"Other Units-based Sensor",    // 0Bh
		"Memory",                      // 0Ch
		"Drive Slot",                  // 0Dh
		"POST Memory Resize",          // 0Eh
		"System Firmware",             // 0Fh
		"Event Logging Disabled",      // 10h
		"Watchdog 1",                  // 11h
		"System Event",                // 12h
		"Critical Interrupt",          // 13h
		"Button / Switch",             // 14h
		"Module / Board",              // 15h
		"Microcontroller",             // 16h
		"Add-in Card",                 // 17h
		"Chassis",                     // 18h
		"Chip Set",                    // 19h
		"Other FRU",                   // 1Ah
		"Cable / Interconnect",        // 1Bh
		"Terminator",                  // 1Ch
		"System Boot Initiated",       // 1Dh
		"Boot Error",                  // 1Eh
		"OS Boot",                     // 1Fh
		"OS Stop",                     // 20h
		"Slot / Connector",            // 21h
		"System ACPI Power State",     // 22h
		"Watchdog 2",                  // 23h
		"Platform Alert",              // 24h
		"Entity Presence",             // 25h
		"Monitor ASIC",                // 26h
		"LAN",                         // 27h
		"Management Subsystem Health", // 28h
		"Battery",                     // 29h
		"Session Audit",               // 2Ah
		"Version Change",              // 2Bh
		"FRU State",                   // 2Ch
	}
	i := int(t)
	if i < len(sensorType) {
		return sensorType[i]
	}
	if i < 0xc0 {
		return fmt.Sprintf("Reserved(%d)", i)
	}
	return fmt.Sprintf("OEM RESERVED(%d)", i)
}

// Sensor Unit Type (Section 43.17)
type UnitType uint8

func (u UnitType) String() string {
	units := []string{
		"unspecified",         // 00
		"degrees C",           // 01
		"degrees F",           // 02
		"degrees K",           // 03
		"Volts",               // 04
		"Amps",                // 05
		"Watts",               // 06
		"Joules",              // 07
		"Coulombs",            // 08
		"VA",                  // 09
		"Nits",                // 10
		"lumen",               // 11
		"lux",                 // 12
		"Candela",             // 13
		"kPa",                 // 14
		"PSI",                 // 15
		"Newton",              // 16
		"CFM",                 // 17
		"RPM",                 // 18
		"Hz",                  // 19
		"microsecond",         // 20
		"millisecond",         // 21
		"second",              // 22
		"minute",              // 23
		"hour",                // 24
		"day",                 // 25
		"week",                // 26
		"mil",                 // 27
		"inches",              // 28
		"feet",                // 29
		"cu in",               // 30
		"cu feet",             // 31
		"mm",                  // 32
		"cm",                  // 33
		"m",                   // 34
		"cu cm",               // 35
		"cu m",                // 36
		"liters",              // 37
		"fluid ounce",         // 38
		"radians",             // 39
		"steradians",          // 40
		"revolutions",         // 41
		"cycles",              // 42
		"gravities",           // 43
		"ounce",               // 44
		"pound",               // 45
		"ft-lb",               // 46
		"oz-in",               // 47
		"gauss",               // 48
		"gilberts",            // 49
		"henry",               // 50
		"millihenry",          // 51
		"farad",               // 52
		"microfarad",          // 53
		"ohms",                // 54
		"siemens",             // 55
		"mole",                // 56
		"becquerel",           // 57
		"PPM",                 // 58
		"reserved",            // 59
		"Decibels",            // 60
		"DbA",                 // 61
		"DbC",                 // 62
		"gray",                // 63
		"sievert",             // 64
		"color temp deg K",    // 65
		"bit",                 // 66
		"kilobit",             // 67
		"megabit",             // 68
		"gigabit",             // 69
		"byte",                // 70
		"kilobyte",            // 71
		"megabyte",            // 72
		"gigabyte",            // 73
		"word",                // 74
		"dword",               // 75
		"qword",               // 76
		"line",                // 77
		"hit",                 // 78
		"miss",                // 79
		"retry",               // 80
		"reset",               // 81
		"overflow",            // 82
		"underrun",            // 83
		"collision",           // 84
		"packets",             // 85
		"messages",            // 86
		"characters",          // 87
		"error",               // 88
		"correctable error",   // 89
		"uncorrectable error", // 90
		"fatal error",         // 91
		"grams",               // 92
	}
	if i := int(u); i < len(units) {
		return units[i]
	}
	return fmt.Sprintf("unknown(%d)", u)
}
