package net

import (
	"strconv"
	"strings"
	"syscall"

	"github.com/eoidc/gopsutil/internal/common"
)

func IOCountersByFile(pernic bool, filename string) ([]IOCountersStat, error) {
	lines, err := common.ReadLines(filename)
	if err != nil {
		return nil, err
	}

	parts := make([]string, 2)

	statlen := len(lines) - 1

	ret := make([]IOCountersStat, 0, statlen)

	//initial a socket for ioctl
	fd, _, ep := syscall.RawSyscall(syscall.SYS_SOCKET, syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_IP)
	if ep == 0 {
		defer syscall.Close(int(fd))
	}

	//the map is all the interface which are belong to bond
	knownByBond := make(map[string]slaveInfo)

	for _, line := range lines[2:] {
		separatorPos := strings.LastIndex(line, ":")
		if separatorPos == -1 {
			continue
		}
		parts[0] = line[0:separatorPos]
		parts[1] = line[separatorPos+1:]

		interfaceName := strings.TrimSpace(parts[0])
		if interfaceName == "" {
			continue
		}

		fields := strings.Fields(strings.TrimSpace(parts[1]))
		bytesRecv, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			return ret, err
		}
		packetsRecv, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return ret, err
		}
		errIn, err := strconv.ParseUint(fields[2], 10, 64)
		if err != nil {
			return ret, err
		}
		dropIn, err := strconv.ParseUint(fields[3], 10, 64)
		if err != nil {
			return ret, err
		}
		fifoIn, err := strconv.ParseUint(fields[4], 10, 64)
		if err != nil {
			return ret, err
		}
		bytesSent, err := strconv.ParseUint(fields[8], 10, 64)
		if err != nil {
			return ret, err
		}
		packetsSent, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			return ret, err
		}
		errOut, err := strconv.ParseUint(fields[10], 10, 64)
		if err != nil {
			return ret, err
		}
		dropOut, err := strconv.ParseUint(fields[11], 10, 64)
		if err != nil {
			return ret, err
		}
		fifoOut, err := strconv.ParseUint(fields[12], 10, 64)
		if err != nil {
			return ret, err
		}

		nic := IOCountersStat{
			Name:        interfaceName,
			BytesRecv:   bytesRecv,
			PacketsRecv: packetsRecv,
			Errin:       errIn,
			Dropin:      dropIn,
			Fifoin:      fifoIn,
			BytesSent:   bytesSent,
			PacketsSent: packetsSent,
			Errout:      errOut,
			Dropout:     dropOut,
			Fifoout:     fifoOut,
		}

		bond, err := getBondInfo(int(fd), interfaceName)
		if err == nil {
			nic.IsBond = true
			for _, slave := range bond.slaves {
				knownByBond[slave.name] = slave
			}
		}

		ret = append(ret, nic)
	}

	for i := 0; i < len(ret); i++ {
		if known, ok := knownByBond[ret[i].Name]; ok {
			if known.linkStat == 0 {
				ret[i].LinkStat = LinkUp
			} else {
				ret[i].LinkStat = LinkDown
			}

			if known.activeStat == 0 {
				ret[i].ActiveStat = SlaveActive
			} else {
				ret[i].ActiveStat = SlaveInActive
			}
		} else {
			ret[i].LinkStat = getLinkStat(int(fd), ret[i].Name)
			ret[i].ActiveStat = 0
		}
	}

	if pernic == false {
		return getIOCountersAll(ret)
	}

	return ret, nil
}
