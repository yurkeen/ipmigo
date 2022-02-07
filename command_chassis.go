package ipmigo

import (
	"encoding/binary"
	"time"
)

// Get Chassis Status Command (Section 28.2)
type GetChassisStatusCommand struct {
	// Response Data
	PowerIsOn               bool
	PowerOverload           bool
	PowerInterlock          bool
	PowerFault              bool
	PowerControlFault       bool
	PowerRestorePolicy      uint8 // (See Table 28-3)
	LastPowerEventACFailed  bool
	LastPowerEventOverload  bool
	LastPowerEventInterlock bool
	LastPowerEventFault     bool
	LastPowerEventCommand   bool
	ChassisIntrusionActive  bool
	FrontPanelLockoutActive bool
	DriveFault              bool
	CoolingFanFault         bool
}

func (c *GetChassisStatusCommand) Name() string             { return "Get Chassis Status" }
func (c *GetChassisStatusCommand) Code() uint8              { return 0x01 }
func (c *GetChassisStatusCommand) NetFnRsLUN() NetFnRsLUN   { return NewNetFnRsLUN(NetFnChassisReq, 0) }
func (c *GetChassisStatusCommand) String() string           { return cmdToJSON(c) }
func (c *GetChassisStatusCommand) Marshal() ([]byte, error) { return []byte{}, nil }

func (c *GetChassisStatusCommand) Unmarshal(buf []byte) ([]byte, error) {
	if err := cmdValidateLength(c, buf, 3); err != nil {
		return nil, err
	}
	c.PowerIsOn = buf[0]&0x01 != 0
	c.PowerOverload = buf[0]&0x02 != 0
	c.PowerInterlock = buf[0]&0x04 != 0
	c.PowerFault = buf[0]&0x08 != 0
	c.PowerControlFault = buf[0]&0x10 != 0
	c.PowerRestorePolicy = buf[0] & 0x60 >> 5

	c.LastPowerEventACFailed = buf[1]&0x01 != 0
	c.LastPowerEventOverload = buf[1]&0x02 != 0
	c.LastPowerEventInterlock = buf[1]&0x04 != 0
	c.LastPowerEventFault = buf[1]&0x08 != 0
	c.LastPowerEventCommand = buf[1]&0x10 != 0

	c.ChassisIntrusionActive = buf[2]&0x01 != 0
	c.FrontPanelLockoutActive = buf[2]&0x02 != 0
	c.DriveFault = buf[2]&0x04 != 0
	c.CoolingFanFault = buf[2]&0x08 != 0
	return nil, nil
}

type ChassisPowerState uint8

const (
	// Force system into soft off (S4/S45) state. This is for ‘emergency’
	// management power down actions. The command does not initiate a clean
	// shut-down of the operating system prior to powering down the system.
	// 0h
	PowerDown ChassisPowerState = iota

	// Power Up.
	// 1h
	PowerUp

	// This command provides a power off intervalof at least 1 second
	// following the deassertion of the system’s POWERGOOD status from
	// the main power subsystem. It is recommended that no action occur
	// if system power is off (S4/S5) when this action is selected, and
	// that a D5h 'Request parameter(s) not supported in present state.'
	// error completion code be returned. Note that some implementations
	// may cause a system power up if a power cycle operation is selected
	// when system power is down. For consistency of operation, it is
	// recommended that system management software first check the system
	// power state before issuing a power cycle, and only issue the
	// command if system power is ON or in a lower sleep state than S4/S5.
	// 2h
	PowerCycle

	// In some implementations, the BMC may not know whether a reset will
	// cause any particular effect and will pulse the system reset signal
	// regardless of power state. If the implementation can tell that no
	//action will occur if a reset is delivered in a given power state,
	// then it is recommended (but still optional) that a D5h 'Request
	// parameter(s) not supported in present state.' error completion code
	// be returned.
	// 3h
	PowerResetHard

	// Pulse a version of a diagnostic interrupt that goes directly to the
	// processor(s). This is typically used to cause the operating system
	// to do a diagnostic dump (OS dependent). The interrupt is commonly
	// an NMI on IA-32 systems and an INIT on Intel® ItaniumTM processor
	// based systems.
	// 4h
	PowerDiagInterrupt

	// Initiate a soft-shutdown of OS via ACPI by emulating a fatal
	// overtemperature.
	// 5h
	PowerSoftACPIDown
)

// Set Chassis Power Command (Section 28.3)
type SetChassisControlCommand struct {
	// Request Data
	PowerState ChassisPowerState
}

func (c *SetChassisControlCommand) Name() string           { return "Set Chassis Power" }
func (c *SetChassisControlCommand) Code() uint8            { return 0x02 }
func (c *SetChassisControlCommand) NetFnRsLUN() NetFnRsLUN { return NewNetFnRsLUN(NetFnChassisReq, 0) }
func (c *SetChassisControlCommand) String() string         { return cmdToJSON(c) }
func (c *SetChassisControlCommand) Marshal() ([]byte, error) {
	return []byte{byte(c.PowerState)}, nil
}

func (c *SetChassisControlCommand) Unmarshal(buf []byte) ([]byte, error) { return nil, nil }

// Get System Restart Cause Command (Section 28.11)
type GetSystemRestartCauseCommand struct {
	// Response Data
	RestartCause uint8 // (See Table 28-11)
}

func (c *GetSystemRestartCauseCommand) Name() string { return "Get System Restart Cause" }
func (c *GetSystemRestartCauseCommand) Code() uint8  { return 0x07 }

func (c *GetSystemRestartCauseCommand) NetFnRsLUN() NetFnRsLUN {
	return NewNetFnRsLUN(NetFnChassisReq, 0)
}

func (c *GetSystemRestartCauseCommand) String() string           { return cmdToJSON(c) }
func (c *GetSystemRestartCauseCommand) Marshal() ([]byte, error) { return []byte{}, nil }

func (c *GetSystemRestartCauseCommand) Unmarshal(buf []byte) ([]byte, error) {
	if err := cmdValidateLength(c, buf, 1); err != nil {
		return nil, err
	}
	c.RestartCause = buf[0]
	return buf[1:], nil
}

// Get POH Counter Command (Section 28.14)
type GetPOHCounterCommand struct {
	// Response Data
	MinutesPerCount uint8
	Counter         uint32
}

func (c *GetPOHCounterCommand) Name() string             { return "Get POH Counter" }
func (c *GetPOHCounterCommand) Code() uint8              { return 0x0f }
func (c *GetPOHCounterCommand) NetFnRsLUN() NetFnRsLUN   { return NewNetFnRsLUN(NetFnChassisReq, 0) }
func (c *GetPOHCounterCommand) String() string           { return cmdToJSON(c) }
func (c *GetPOHCounterCommand) Marshal() ([]byte, error) { return []byte{}, nil }

func (c *GetPOHCounterCommand) Unmarshal(buf []byte) ([]byte, error) {
	if err := cmdValidateLength(c, buf, 5); err != nil {
		return nil, err
	}
	c.MinutesPerCount = uint8(buf[0])
	c.Counter = binary.LittleEndian.Uint32(buf[1:5])
	return buf[5:], nil
}

func (c *GetPOHCounterCommand) PowerOnHours() time.Duration {
	return time.Duration(c.MinutesPerCount) * time.Duration(c.Counter) * time.Minute
}
